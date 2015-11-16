# -*- coding: utf-8 -*-
import csv
import os
import sys
import db_reader
import time
from collections import defaultdict
from execute import execute

reload(sys)
sys.setdefaultencoding('UTF-8')
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')


class Reader(object):
    '''
        Parse scan result and keep it in local variable.
    '''
    def __init__(self):
        self._networks = defaultdict(dict)
        self._clients = defaultdict(dict)
        self.soft_ap = False
        soft_mac_list = ['2', '3', '6', '7', 'A', 'B', 'E', 'F']

        # Copy and remove \x00 character.
        scan_result_file = './log/air_scan_result' + '-01.csv'  # 'airodump' add a number such as -01 when save the file.
        new_csv_file = './log/air_scan_result.csv'

        tmp_csv = open(scan_result_file, 'rb')
        scanned_data = tmp_csv.read()
        tmp_csv.close()

        new_csv = open(new_csv_file, 'wb')
        new_csv.write(scanned_data.replace('\x00', ''))
        new_csv.close()

        with open(new_csv_file, 'rU') as f:
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
    '''
        airodump-ng
    '''
    def __init__(self, iface):
        self.iface = iface
        self.START_SIGNAL = True    # Meaningless variable.
        self.air_scan_result = './log/air_scan_result'
        self._networks = defaultdict(lambda: {'clients': set()})
        self._clients = defaultdict(dict)
        self.dump_proc = False

    def run(self):
        ''' Start airodump-ng and dump '''
        remove_command = 'rm -rf ' + self.air_scan_result + '*'
        execute(remove_command)
        dump_command = ['airodump-ng', self.iface, '-w', self.air_scan_result, '--output-format', 'csv']
        self.dump_proc, unused_ret, unused_out, unused_err = execute(dump_command, wait=False)

    def stop(self):
        if self.dump_proc:
            self.dump_proc.kill()
            self.dump_proc.communicate()
        self.dump_proc = False

    def get_value(self):
        try:
            r = Reader()
            self._networks = r.get_sorted_networks()
            self._clients = r.client_return().values()
        except Exception, e:
            print e
            return False
        return self._networks + self._clients
