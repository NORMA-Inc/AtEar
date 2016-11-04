import fcntl
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from scapy.all import *
import commands
from subprocess import Popen
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__author__ = 'hackpupu'
import re
import random
import urllib2 as urllib
from ctypes import *
from execute import execute
import signal


_dev_name_list = ['atear_dump', 'atear_wids','atear_deauth', 'atear_pentest', 'atear_ap']

def myip():
    return IPgetter().get_externalip()


class Sockaddr(Structure):
    _fields_ = [('sa_family', c_ushort), ('sa_data', c_char * 14)]


class Ifa_Ifu(Union):
    _fields_ = [('ifu_broadaddr', POINTER(Sockaddr)),
                ('ifu_dstaddr', POINTER(Sockaddr))]


class Ifaddrs(Structure):
    pass

Ifaddrs._fields_ = [('ifa_next', POINTER(Ifaddrs)), ('ifa_name', c_char_p),
                    ('ifa_flags', c_uint), ('ifa_addr', POINTER(Sockaddr)),
                    ('ifa_netmask', POINTER(Sockaddr)), ('ifa_ifu', Ifa_Ifu),
                    ('ifa_data', c_void_p)]


class IPgetter(object):
    def __init__(self):
        self.server_list = ['http://ip.dnsexit.com',
                            'http://ifconfig.me/ip',
                            'http://ipecho.net/plain',
                            'http://checkip.dyndns.org/plain',
                            'http://ipogre.com/linux.php',
                            'http://whatismyipaddress.com/',
                            'http://ip.my-proxy.com/',
                            'http://websiteipaddress.com/WhatIsMyIp',
                            'http://getmyipaddress.org/',
                            'http://www.my-ip-address.net/',
                            'http://myexternalip.com/raw',
                            'http://www.canyouseeme.org/',
                            'http://www.trackip.net/',
                            'http://icanhazip.com/',
                            'http://www.iplocation.net/',
                            'http://www.howtofindmyipaddress.com/',
                            'http://www.ipchicken.com/',
                            'http://whatsmyip.net/',
                            'http://www.ip-adress.com/',
                            'http://checkmyip.com/',
                            'http://www.tracemyip.org/',
                            'http://checkmyip.net/',
                            'http://www.lawrencegoetz.com/programs/ipinfo/',
                            'http://www.findmyip.co/',
                            'http://ip-lookup.net/',
                            'http://www.dslreports.com/whois',
                            'http://www.mon-ip.com/en/my-ip/',
                            'http://www.myip.ru',
                            'http://ipgoat.com/',
                            'http://www.myipnumber.com/my-ip-address.asp',
                            'http://www.whatsmyipaddress.net/',
                            'http://formyip.com/',
                            'https://check.torproject.org/',
                            'http://www.displaymyip.com/',
                            'http://www.bobborst.com/tools/whatsmyip/',
                            'http://www.geoiptool.com/',
                            'https://www.whatsmydns.net/whats-my-ip-address.html',
                            'https://www.privateinternetaccess.com/pages/whats-my-ip/',
                            'http://checkip.dyndns.com/',
                            'http://myexternalip.com/',
                            'http://www.ip-adress.eu/',
                            'http://www.infosniper.net/',
                            'http://wtfismyip.com/',
                            'http://ipinfo.io/',
                            'http://httpbin.org/ip']

    def get_externalip(self):
        '''
        This function gets your IP from a random server
        '''

        myip = ''
        for i in range(7):
            myip = self.fetch(random.choice(self.server_list))
            if myip != '':
                return myip
            else:
                continue
        return ''

    def fetch(self, server):
        '''
        This function gets your IP from a specific server.
        '''
        url = None
        opener = urllib.build_opener()
        opener.addheaders = [('User-agent',
                              "Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0")]

        try:
            url = opener.open(server, timeout=2)
            content = url.read()

            # Didn't want to import chardet. Prefered to stick to stdlib
            try:
                content = content.decode('UTF-8')
            except UnicodeDecodeError:
                content = content.decode('ISO-8859-1')

            m = re.search(
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                content)
            myip = m.group(0)
            return myip if len(myip) > 0 else ''
        except Exception:
            return ''
        finally:
            if url:
                url.close()


def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
    except IOError:
        return False


def get_l_gateway_ip(iface):
    command = "route |grep "+iface+"| grep default | awk -F' ' '{print $2}'"
    p, ret, out, err = execute(command)
    gw_address = out.replace('\n', '')

    return gw_address


def get_l_gateway_mac(iface):
    command = '/usr/bin/arping -c 1 -I ' + iface + ' ' + get_l_gateway_ip(iface)
    p, r, output, e = execute(command)
    if output is not None:
        mac_address = re.findall(r'(\[.*\])', output)[0].replace('[', '').replace(']', '')
        return mac_address
    else:
        return False


def get_remote_mac(iface, ipaddr):
    command = '/usr/bin/arping -c 1 -I ' + iface + ' ' + ipaddr
    p, r, output, e = execute(command)
    if output is not None:
        try:
            mac_address = re.findall(r'(\[.*\])', output)[0].replace('[', '').replace(']', '')
            return mac_address
        except IndexError:
            return False
    else:
        return False


def network_host_ip(interface):
    # interface subnet mask calc
    subnet = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET,
                                                        socket.SOCK_DGRAM),
                                          35099,
                                          struct.pack('256s', interface))[20:24])
    subnet = subnet.split('.')
    binary_str = ''
    for octet in subnet:
        binary_str += bin(int(octet))[2:].zfill(8)
    subnet = str(len(binary_str.rstrip('0')))
    # interface ip calc
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', interface[:15])
    )[20:24])
    # Network Scan Start
    parser = None
    process = NmapProcess(targets=ip + '/' + subnet, options="-sP", event_callback=None, safe_mode=None, fqp=None)
    rc = process.run()
    if rc != 0:
        print("Network Scan Failed")

    try:
        parser = NmapParser.parse(process.stdout)
    except NmapParserException:
        print("Exception Network Error")
    up_hosts = []

    gateway = get_l_gateway_ip(interface)
    for host in parser.hosts:
        if str(host).find('up') is not -1:
            up_host = re.findall(r'(\[.*\()', str(host))[0].replace('[', '').replace(' (', '')
            up_hosts.append(up_host)

    up_hosts.remove(gateway)
    up_hosts.remove(ip)
    return ' / '.join(up_hosts)

def monitormode_change(iface, managed_flag = False):
    cmd = "rfkill unblock wlan"
    Popen(cmd, shell=True).communicate()
    time.sleep(0.3)
    cmd = "ifconfig %s down"%(iface)
    Popen(cmd, shell=True).communicate()
    time.sleep(0.5)

    cmd = "iwconfig %s mode managed"%(iface)
    Popen(cmd, shell=True).communicate()
    time.sleep(0.5)

    cmd = "ifconfig %s up"%(iface)
    Popen(cmd, shell=True).communicate()
    time.sleep(0.5)
    if not managed_flag:
        cmd = "ifconfig %s down"%(iface)
        Popen(cmd, shell=True).communicate()
        time.sleep(0.5)

        cmd = "iwconfig %s mode monitor"%(iface)
        Popen(cmd, shell=True).communicate()
        time.sleep(0.5)

        cmd = "ifconfig %s up"%(iface)
        Popen(cmd, shell=True).communicate()
        time.sleep(0.5)


def arp_spoof(iface):
    execute('echo 1 > /proc/sys/net/ipv4/ip_forward')
    execute('service whoopsie stop')
    victim_hosts = network_host_ip(iface)
    gateway_ip = get_l_gateway_ip(iface)
    while True:
        for victim_ip in victim_hosts:
            to_gateway = ARP()
            to_gateway.psrc = victim_ip
            to_gateway.pdst = gateway_ip
            to_victim = ARP()
            to_victim.psrc = gateway_ip
            to_victim.pdst = victim_ip
            send(to_victim, verbose=0)
            send(to_gateway, verbose=0)
            time.sleep(5)

def get_ap_info(essid, channel, enc_type, pw, iface, need_public_info=False, need_conn_host_info=False):
    success = False
    public_ip = ''
    conn_host = ''
    if set_new_connection(essid, channel, pw, iface, enc_type):
        if need_public_info:
            public_ip = myip()
        if need_conn_host_info:
            try:
                conn_host = network_host_ip(iface)
            except IOError:
                conn_host = False
    else: # if 'set_new_connection' function return false
        print '[!!] Failed to connect to AP '+ essid
    # Releqse Session
    execute('iw dev '+iface+' disconnect')
    execute('ifconfig '+iface+' down')
    execute('dhcpcd -k '+ iface)
    execute('killall wpa_supplicant')
    return success, public_ip, conn_host


def set_new_connection(essid, channel, pw, iface, enc_type):
    '''
        @brief This function is a part that connects to the AP in pentest module.
            The connection method varies depending on the protocol used.
            Use the iw dev utility to verify that connection.
    '''
    p,r,o,e = execute("ps -ef |grep dhcpcd-bin")
    if o:
        ol = o.split('\n')
        for out1 in ol:
            if out1.find(iface) != -1:
                if out1.split()[1].isdigit():
                    os.kill(int(out1.split()[1]), signal.SIGKILL)
                    print out1.split()[1]

    p,r,o,e = execute("ps -ef |grep dhclient")
    if o:
        ol = o.split('\n')
        for out1 in ol:
            if out1.find(iface) != -1:
                if out1.split()[1].isdigit():
                    os.kill(int(out1.split()[1]), signal.SIGKILL)
                    print out1.split()[1]

    p,r,o,e = execute("ps -ef |grep wpa_supplicant")
    if o:
        ol = o.split('\n')
        for out1 in ol:
            if out1.find(iface) != -1:
                if out1.split()[1].isdigit():
                    os.kill(int(out1.split()[1]), signal.SIGKILL)
                    print out1.split()[1]

    execute('ifconfig '+iface+' down')
    execute('iwconfig '+iface+' mode managed')
    time.sleep(1)
    if "WEP" in enc_type.upper():
        # If AP is encrypted with WEP, connect using the 'iwconfig' utility.
        execute('iwconfig '+iface+' essid '+ essid)
        execute('iwconfig '+iface+' key s:'+ '\''+pw+'\'')
        time.sleep(1)
        execute('ifconfig '+iface+' up')
        time.sleep(3)

        link = commands.getoutput('iw dev '+iface+' link')
        if 'Not connected.' in link: # verify
            return False

        p, r, out, err = execute('dhclient '+iface)
        return True

    elif "WPA" in enc_type.upper():
        # If AP is encrypted with WPA, connect using the 'wpa_supplicant' utility.
        execute('iwconfig '+iface+' essid '+essid)
        proc = Popen('/usr/bin/wpa_passphrase '+essid+' > /etc/wpa_supplicant/wpa_supplicant.conf',\
                     shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        proc.stdin.write(pw)

        execute('/sbin/wpa_supplicant -i '+iface+' -B -c /etc/wpa_supplicant/wpa_supplicant.conf')
        time.sleep(3)
        link = commands.getoutput('iw dev '+iface+' link')
        if 'Not connected.' in link: # verify
            return False
        p, r, out, err = execute('dhcpcd '+ iface+' -t 10') # wait 10 seconds

        # Sometime dhcpcd occur the error and set invalid IP address.
        if "timed out" in err:
            for i in range(0, 5): # retry count 5
                execute('dhcpcd -k '+iface)
                execute('killall wpa_supplicant')
                time.sleep(1)
                execute('/sbin/wpa_supplicant -i '+iface+' -B -c /etc/wpa_supplicant/wpa_supplicant.conf')
                time.sleep(1)
                p, r, out, err = execute('dhcpcd '+ iface+' -t 10') # wait 10 seconds
                if "timed out" not in err: # quit loop
                    break
                elif i == 4: # 4 is last chance
                    return False
        return True

    elif "OPN" in enc_type.upper():
        # If AP is encrypted with WPA, connect using the 'iw' utility.
        execute('ifconfig '+iface+' up')
        execute('iw dev '+iface+' connect '+essid)
        time.sleep(1)
        if commands.getoutput('iw dev '+iface+' link') is 'Not connected.': # verify
            return False
        execute('dhclient '+iface)
        return True


def get_interfaces():
    libc = CDLL('libc.so.6')
    libc.getifaddrs.restype = c_int
    ifaddr_p = pointer(Ifaddrs())
    ret = libc.getifaddrs(pointer((ifaddr_p)))
    interfaces = set()
    head = ifaddr_p
    while ifaddr_p:
        interfaces.add(ifaddr_p.contents.ifa_name)
        ifaddr_p = ifaddr_p.contents.ifa_next
    libc.freeifaddrs(head)
    return interfaces

def disable_wlan_interface():
    p,r,o,e = execute("iwconfig |grep wlan |awk '{print $1}'")
    intf_list = o.split('\n')
    for intf in intf_list:
        execute("ifconfig %s down"%(intf))

def is_fit_in(interface):

    isSupportMon = False
    isSupportAP = False
    p, r, out, err = execute('iw phy '+interface+' info |grep "Supported interface modes" -A 10 |grep "*"')
    support_list = out.replace('\t', '').replace('*', '').replace(' ','').split('\n')

    for support in support_list:
        if support == 'AP':
            isSupportAP = True
        elif support == 'monitor':
            isSupportMon = True

    if isSupportAP and isSupportMon:
        return True
    else:
        return False


def auto_monitor():
    '''
        @brief Check monitor mode support. and set.
    '''
    stop_monitor()
    disable_wlan_interface()

    # Get Wireless Interface
    p, r, out, err = execute('iw dev| grep phy')
    interface_list = out.replace('#','').split('\n')
    interface_list.pop()

    print "[*] Check Monitor mode...."
    isAPSupport = False
    isMonSupport = False
    if not interface_list:
        print "\nCouldn't find Wireless device"
        return False

    interface = None
    for intf in interface_list:
        if is_fit_in(intf):
            interface = intf
            break

    if interface == None:
        print '\n'
        print '[!!] Could not find the device to support the required mode.'
        print '[!!] Please check that the WLAN device that supports monitor mode on your system.'
        return False

    # Make Interface at monitor mode
    print "[*] Set Monitor mode...."
    for dev in _dev_name_list:
        execute('iw phy ' + interface + ' interface add '+ dev +' type monitor')
        time.sleep(0.5)
        if set_monitor_mode(dev) == False: # if Fail to Set up Monitor mode
            print '[!!] It failed to change the mode of the wireless LAN device.'
            print '[!!] Please try again later.'
            return False

    execute('rfkill unblock wlan')
    return True


def set_monitor_mode(dev):
    '''
        @brief Set wlan device to monitor mode.
        @return:
            * success - True
            * fail - False
    '''
    cmd = "ifconfig %s down;iwconfig %s mode monitor;ifconfig %s up" %(dev, dev, dev)
    execute(cmd)
    time.sleep(0.5)

    p, r, out, e = execute('iwconfig '+ dev)
    if "Mode:Monitor" not in out:
        return False

    return True


def stop_monitor():
    '''
        @brief Delete wlan device.
    '''
    for dev in _dev_name_list:
        execute('iw dev '+ dev +' del > /dev/null 2>&1')
    #w_interface_up()


def w_interface_down():
    p, retval, out, err = execute('iw dev |grep Interface')
    intf_list = out.replace('\tInterface','').split()
    for interface in intf_list:
        execute('ifconfig ' + interface + ' down')


def w_interface_up():
    p, retval, out, err = execute('iw dev |grep Interface')
    intf_list = out.replace('\tInterface','').split()
    for interface in intf_list:
        execute('ifconfig ' + interface + ' up')



#print get_interfaces()