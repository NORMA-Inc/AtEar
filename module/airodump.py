# -*- coding: utf-8 -*-
import csv
import os
from subprocess import Popen
import sys
import db_reader
from collections import defaultdict

reload(sys)
sys.setdefaultencoding('UTF-8')
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')


class Reader(object):
    def __init__(self):
        self._networks = defaultdict(dict)
        self._clients = defaultdict(dict)
        self.soft_ap = False
        soft_mac_list = ['2', '3', '6', '7', 'A', 'B', 'E', 'F']
        tmp_csv = open('/tmp/atear-01.csv', 'rb')
        data = tmp_csv.read()
        tmp_csv.close()
        new_csv = open('/tmp/atear.csv', 'wb')
        new_csv.write(data.replace('\x00', ''))
        new_csv.close()
        csv_path = '/tmp/atear.csv'
        with open(csv_path, 'rU') as f:
            parsing_networks = True
            for line in csv.reader(f):
                if not line or line[0] == 'BSSID':
                    continue
                if line[0] == 'Station MAC':
                    parsing_networks = False
                    continue
                line = map(str, line)
                if parsing_networks:
                    company = db_reader.oui_search(line[0])
                    if line[0][1] in soft_mac_list:
                        self.soft_ap = True
                    try:
                        self[line[0]].update({
                            'company': company,
                            'product': db_reader.product_search(line[0]),
                            'essid': line[13][1:],
                            'bssid': line[0],
                            'ch': int(line[3]),
                            'power': int(line[8]),
                            'enc': line[5] + line[6],
                            'Time': line[2],
                            'nb_data': int(line[10]),
                            'nb_beacons': int(line[9]),
                            'sid_length': int(line[12]),
                        })
                    except:
                        pass
                    try:
                        if self.soft_ap:
                            self[line[0]].update({
                                'type': 'SoftAp',
                            })
                            self.soft_ap = False
                        elif line[8] == -1:
                            self[line[0]].update({
                                'type': 'ad-hoc',
                            })
                        else:
                            self[line[0]].update({
                                'type': 'Access Point',
                            })
                    except:
                        pass
                else:
                    try:
                        sta_type = 'station'
                        if int(line[3]) == -1:
                            sta_type = 'ad-hoc'
                        self._clients[line[0]].update({
                            'type': sta_type,
                            'bssid': line[0],
                            'Time': line[2],
                            'essid': line[5].strip(),
                            'power': int(line[3]),
                            'nb_data': line[4],
                            'probes': line[6].split(', '),
                            'company': db_reader.oui_search(line[0]),
                            'product': db_reader.product_search(line[0]),
                        })
                    except:
                        pass

    def __getitem__(self, item):
        return self._networks[item]

    def __setitem__(self, item, value):
        self._networks[item] = value

    def client_return(self):
        return self._clients

    def get_sorted_networks(self):
        return sorted(filter(lambda d: 'bssid' in d, self._networks.values()), key=lambda net: -net['power'])


class Scanner(object):
    def __init__(self, iface):
        self.iface = iface
        self.PATH = '/tmp/'
        self._networks = defaultdict(lambda: {'clients': set()})
        self._clients = defaultdict(dict)
        self.dump_proc = False

    def run(self):
        ''' Start airodump-ng and dump '''
        remove_command = 'rm -rf ' + self.PATH + 'atear-*'
        # Unused try and except, No Possibility.
        try:
            Popen(remove_command, shell=True, stdout=None, stderr=None)
        except OSError:
            pass
        dump_command = ['airodump-ng', self.iface, '-w', self.PATH + 'atear', '--channel', '1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,161,165,169,38,46,54,62,102,110,118,126,134,142,151,157,159,42,58,106,122,138,155,50,114']
        self.dump_proc = Popen(dump_command, stdout=DN, stderr=DN)

    def stop(self):
        if self.dump_proc:
            self.dump_proc.kill()
        self.dump_proc = False

    def get_value(self):
        try:
            self._networks = Reader().get_sorted_networks()
            self._clients = Reader().client_return().values()
        except:
            return False
        return self._networks + self._clients