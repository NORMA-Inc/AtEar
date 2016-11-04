# -*- coding: utf-8 -*-
import csv
import os
import sys
import db_reader
import commands
import re
from collections import defaultdict
from execute import execute
from subprocess import Popen, PIPE
from threading import Thread
reload(sys)
sys.setdefaultencoding('UTF-8')
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

class Command_thread(Thread):
    def __init__ (self, command, callback=None):
        Thread.__init__(self)
        self.command = command
        self.callback = callback
    def run(self):
        commands.getoutput(self.command)
        # callback
        if hasattr(self.callback, '__call__'):
            self.callback()

class Reader(object):
    '''
        Parse scan result and keep it in local variable.
    '''
    def __init__(self):
        self.aps = defaultdict()
        self.clients = defaultdict()
        self.channel_list = []
        self.soft_mac_list = ['2','3','6','7','A','B','E','F']

        output_raw = commands.getoutput('cat /tmp/atear-scan-01.csv')
        output = output_raw.split("\n")
        for out in output:
            match = re.match(
                r"([0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2})\s*,\s*\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2}\s*,\s*(\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2})\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\w+)\s*,\s*([\w\s]*)\s*,\s*(\w*)\s*,\s*(.\d+)\s*,\s*\d+\s*,\s*(\d+)\s*,.+,\s*(.+)\s*,.*",
                out)
            if match:
                company = db_reader.oui_search(str(match.group(1)))
                if str(match.group(1))[1] in self.soft_mac_list:
                    ap_type = 'SoftAp'
                elif int(match.group(8)) == -1:
                    ap_type =  'ad-hoc',
                else:
                    ap_type =  'Access Point'

                self.aps[match.group(1)] = {
                    'type' : ap_type,
                    'company':company,
                    'product' : 'unknown',
                    'nd_beacons': 0,
                    'sid_length' : 0,
                    'Time': match.group(2),
                    'ch': match.group(3),
                    "enc": match.group(5),
                    'cipher': match.group(6),
                    'auth': match.group(7),
                    'power':match.group(8),
                    'nb_data': match.group(9),
                    'essid':match.group(10),
                    'bssid':match.group(1),
                }

            else:
                matchb = re.match(
                    r"([0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2}:[0-9A-Fa-f]{2,2})\s*,\s*\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2}\s*,\s*(\d{4,4}-\d{2,2}-\d{2,2}\s*\d{2,2}:\d{2,2}:\d{2,2})\s*,\s*(.\d+)\s*,\s*(\d+)\s*,\s*(.+)\s*,.*",
                    out)
                if not matchb:
                    continue
                else:
                    if "WPA" in matchb.group(5) or "OPN" in matchb.group(5) or "WEP" in matchb.group(
                            5) or "WPA2" in matchb.group(5):
                        pass
                    else:
                        company = db_reader.oui_search(str(matchb.group(1)))
                        sta_type = 'station'
                        if int(matchb.group(3)) == -1:
                            sta_type = 'ad-hoc'
                        sta_bssid = str(matchb.group(1)).upper()
                        ap_bssid = str(matchb.group(5)).upper()

                        if "NOT ASSOCIATED" in ap_bssid:
                            ap_bssid = 'notasso'
                        duplicated_flag = False
                        if sta_bssid in self.aps:
                            duplicated_flag = True

                        self.clients[sta_bssid] = {
                            'bssid':sta_bssid,
                            'essid': ' ',
                            'type': sta_type,
                            'Time': str(matchb.group(2)),
                            "nb_data": str(matchb.group(4)),
                            'probes': ' ',
                            'power': str(matchb.group(3)),
                            'company': company,
                            'duplicated': duplicated_flag,
                        }


    def client_return(self):
        return self.clients

    def aps_return(self):
        return self.aps

class Scanner(object):
    '''
        airodump-ng
    '''
    def __init__(self, iface):
        self.interface = iface
        self.isRunning = False    # Meaningless variable.
        self._networks = defaultdict(dict)
        self._clients = defaultdict(dict)
        self.channel_list = []

    def get_channel_list(self):
        proc = Popen('iwlist %s channel|grep Channel' % (self.interface), shell=True, stdout=PIPE)
        out = proc.communicate()[0]
        chpt = re.compile('^Channel \d*')
        for line in out.split('\n'):
            line = line.lstrip()
            if chpt.match(line):
                self.channel_list.append(int(line.split()[1]))
        channel_list = str(self.channel_list).replace('[', '')
        channel_list = str(channel_list.replace(']', ''))
        channel_list = str(channel_list.replace(' ', ''))
        return channel_list

    def stop(self):
        print '[*] Stop Scanning networkp'
        commands.getstatusoutput('killall airodump-ng')
        self.isRunning = False

    def run(self):
        print '[*] Start scanning network '
        commands.getstatusoutput('rm -r /tmp/atear-scan-01.csv*')
        scan_command = 'airodump-ng --output-format csv --write /tmp/atear-scan'
        scan_command = scan_command + ' --channel ' + str(self.get_channel_list())
        scan_command = str(scan_command + ' ' + self.interface)
        ct = Command_thread(scan_command)
        ct.start()
        self.isRunning = True

    def get_value(self):
        try:
            r = Reader()
            self._networks = r.aps_return().values()
            self._clients = r.client_return().values()
        except Exception, e:
            print e
            return False
        return self._networks + self._clients
