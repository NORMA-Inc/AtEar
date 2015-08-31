__author__ = 'root'
from subprocess import Popen, PIPE
import os
import datetime
import time


class Wireless_IDS():
    def __init__(self, iface):
        self.START_SIG = True
        self.iface = iface
        self.captured_csv = '/tmp/atear_wids.csv'
        self.tcpdump_cap = '/tmp/atear_wids.pcap'
        self.tcpdump_log = '/tmp/tcpdump.log'
        self.essidfile = '/tmp/essidcount.log'
        self.essidlog = '/tmp/essidlog.txt'
        self.resultlist = '/tmp/resultlist.log'
        self.macfile = '/tmp/macfile.log'
        self.resultlog = '/tmp/result.log'
        self.logfile = '/tmp/log.txt'
        self.recent_logfile = '/tmp/recent_log.txt'
        self.json_logfile = '/tmp/json_log.txt'
        self.L_FrMAC = []
        self.L_ToMAC = []
        self.L_Data = []
        self.L_Auth = []
        self.L_Deauth = []
        self.L_Assoc = []
        self.L_Reassoc = []
        self.L_Disassoc = []
        self.L_RTS = []
        self.L_CTS = []
        self.L_ACK = []
        self.L_EAPOL = []
        self.L_WPS = []
        self.L_Beacon = []
        self.L_SSID = []
        self.L_SSIDCT = []
        self.L_IsAP = []
        self.L_PResp = []
        self.L_PReq = []
        self.L_ProbeName = []
        self.L_NULL = []
        self.L_QOS = []
        self.L_Data86 = []
        self.L_Data94 = []
        self.L_Data98 = []
        self.MACDetail = ""
        Popen('rm -rf /tmp/atear_wids*', shell=True, stdout=None, stderr=None)
        open(self.essidfile, "wb").write("")
        open(self.macfile, "wb").write("")
        open(self.json_logfile, "wb").write("")
        open(self.essidfile, "wb").write("")
        open(self.essidlog, "wb").write("")
        open(self.resultlist, "wb").write("")
        open(self.macfile, "wb").write("")
        open(self.resultlog, "wb").write("")
        open(self.logfile, "wb").write("")
        open(self.recent_logfile, "wb").write("")
        open(self.json_logfile, "wb").write("")

    def CaptureTraffic(self):
        dump_cmd = 'tshark -i ' + self.iface + ' -w ' + self.tcpdump_cap + ' -n -t ad -a duration:20 > /dev/null 2>&1'
        dump_proc = Popen(dump_cmd, shell=True, stdout=PIPE)
        dump_proc.wait()

    def ConvertPackets(self):
        conv_cmd = 'tshark -r ' + self.tcpdump_cap + ' -n -t ad > ' + self.tcpdump_log
        conv_proc = Popen(conv_cmd, shell=True, stdout=PIPE, stderr=open(os.devnull, 'w'))
        conv_proc.wait()
        tmp_csv = open('/tmp/atear_wids-01.csv', 'rb')
        data = tmp_csv.read()
        tmp_csv.close()
        new_csv = open(self.captured_csv, 'wb')
        new_csv.write(data.replace('\x00', ''))
        new_csv.close()

    def run(self):
        airo_cmd = 'airodump-ng ' + self.iface + ' -w /tmp/atear_wids'
        airo_proc = Popen(airo_cmd, shell=True, stdout=PIPE, stderr=PIPE)
        while self.START_SIG:
            self.CaptureTraffic()
            self.ConvertPackets()
            with open(self.tcpdump_log, 'r') as f:
                for line in f:
                    line = line.replace("\n", "")
                    line = line.replace("(TA)", "")
                    line = line.replace("(RA)", "")
                    line = line.replace("(BSSID)", "")
                    if len(line) > 15:
                        line = line.replace("[Malformed Packet]", "")
                        line = line + ", ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., .,"
                        line = line.replace("\r", "")
                        FoundType = ""

                        STYPE = ""
                        DTYPE = ""
                        DTYPE2 = ""
                        DTYPE3 = ""
                        SSID = ""
                        PSSID = ""
                        AESSID = ""
                        FR_MAC = line.split()[3].replace(',', '').upper()
                        TO_MAC1 = line.split()[5].replace(',', '').upper()
                        TO_MAC2 = line.split()[4].replace(',', '').upper()
                        DTYPE = line.split()[8].replace(',', '').upper()
                        DTYPE2 = line.split()[7].replace(',', '').upper()
                        DTYPE3 = line.split()[9].replace(',', '').upper()
                        WPS1 = line.split()[6].replace(',', '').upper()
                        WPS2 = line.split()[11].replace(',', '').upper().replace("FLAGS=", "")
                        WPS3 = line.split()[12].replace(',', '').upper().replace("FLAGS=", "")
                        SSID = line.split(', ')[5].replace(',', '').replace('(', '')
                        PSSID = line.split(', ')[4].replace(',', '').replace('(', '')
                        ATO_MAC = ''

                        if len(TO_MAC1) == 17:
                            ATO_MAC = TO_MAC1
                        if len(TO_MAC2) == 17:
                            ATO_MAC = TO_MAC2

                        if SSID == ".":
                            SSID = ""

                        if PSSID != "" and PSSID[:5] == "SSID=":
                            if PSSID[-18:] == "[Malformed Packet]":
                                PSSID = PSSID[:-18]
                            PSSID = PSSID[5:]
                        else:
                            PSSID = ""

                        if SSID != "" and SSID[:5] == "SSID=":
                            if SSID[-18:] == "[Malformed Packet]":
                                SSID = SSID[:-18]
                            SSID = SSID[5:]
                            AESSID = SSID

                        if line.find(str('EAPOL')) != -1:
                            DTYPE = line.split()[6].replace(',', '').replace(')', '').upper()

                        if len(FR_MAC) == 17 and len(TO_MAC1) == 17:
                            FoundType = 1
                            STYPE = DTYPE
                        if len(TO_MAC2) == 17:
                            FoundType = 2
                            STYPE = DTYPE2
                        if len(FR_MAC) != 17 and len(TO_MAC1) != 17 and len(TO_MAC2) != 17:
                            FoundType = 3
                            STYPE = DTYPE2
                            DTYPEA = str(DTYPE2) + " " + str(DTYPE)
                            if DTYPEA == "RESERVED FRAME":
                                STYPE = DTYPEA
                        if DTYPE == "NULL" and DTYPE3 == "FUNCTION":
                            DTYPEA = str(DTYPE) + " " + str(DTYPE3)
                            STYPE = DTYPEA + ""

                        if DTYPE == "BEACON" and DTYPE3 == "FRAME":
                            DTYPEA = str(DTYPE) + " " + str(DTYPE3)
                            STYPE = DTYPEA
                            FOUND_REC = ""
                            if SSID != "" and len(FR_MAC) == 17:
                                with open(self.essidfile, 'r+') as essidf:
                                    elines = essidf.readlines()
                                    essidf.seek(0)
                                    essidf.truncate()
                                    for eline in elines:
                                        eline = eline.replace("\n", "")
                                        if FR_MAC in eline:
                                            ED_MAC = eline.split(', ')[0]
                                            ED_NAME = eline.split(', ')[1]
                                            ED_CT = eline.split(', ')[2]
                                            if ED_NAME == SSID:
                                                try:
                                                    ED_CT = int(ED_CT) + 1
                                                except ValueError:
                                                    ED_CT = ED_CT
                                                eline = str(FR_MAC) + ", " + str(SSID) + ", " + str(ED_CT)
                                                FOUND_REC = 1
                                        essidf.write(eline + "\n")
                                    if FOUND_REC == "":
                                        essidf.write(FR_MAC + ", " + SSID + ", 1")
                        FOUND_REC = ""
                        if len(FR_MAC) == 17 and len(ATO_MAC) == 17:
                            with open(self.macfile, 'r+') as rf:
                                elines = rf.readlines()
                                rf.seek(0)
                                rf.truncate()
                                for eline in elines:
                                    eline = eline.replace('\n', '')
                                    if FR_MAC in eline:
                                        ED_FRMAC = eline.split(', ')[0].replace(',', '')
                                        ED_TOMAC = eline.split(', ')[1].replace(',', '')
                                        ED_CT = eline.split(', ')[2].replace(',', '')
                                        if ED_TOMAC == ATO_MAC:
                                            try:
                                                ED_CT = int(ED_CT) + 1
                                            except ValueError:
                                                ED_CT = 1
                                            eline = str(FR_MAC) + ", " + str(ATO_MAC) + ", " + str(ED_CT)
                                            FOUND_REC = 1
                                    rf.write(eline + "\n")
                                if FOUND_REC == "":
                                    rf.write(FR_MAC + ", " + ATO_MAC + ", 1")

                        DTYPEA = str(DTYPE) + " " + str(DTYPE3)
                        if DTYPEA == "PROBE RESPONSE":
                            STYPE = DTYPEA
                        if DTYPEA == "PROBE REQUEST":
                            STYPE = DTYPEA

                        if WPS1 == "EAP" and WPS2 == "WPS":
                            STYPE = "WPS"

                        if str(TO_MAC1) == "FF:FF:FF:FF:FF:FF":
                            BCast = 1
                        else:
                            BCast = 0

                        if len(FR_MAC) != 17:
                            FR_MAC = ""
                        if len(TO_MAC1) != 17 and len(TO_MAC2) == 17:
                            TO_MAC1 = TO_MAC2
                        if len(TO_MAC2) != 17:
                            TO_MAC2 = ""
                        if FR_MAC != "":
                            BAK_FR_MAC = FR_MAC

                        open(self.resultlog, "a+b").write("Line : " + str(line) + "\n")
                        open(self.resultlog, "a+b").write("FoundType : " + str(FoundType) + "\n")
                        open(self.resultlog, "a+b").write("STYPE : " + str(STYPE) + "\n")
                        open(self.resultlog, "a+b").write("BCast  : " + str(BCast) + "\n")
                        open(self.resultlog, "a+b").write("FR_MAC : " + str(FR_MAC) + " = " + str(len(FR_MAC)) + "\n")
                        open(self.resultlog, "a+b").write("TO_MAC : " + str(TO_MAC1) + " = " + str(len(TO_MAC1)) + "\n")
                        open(self.resultlog, "a+b").write("TO_MAC2 : " + str(TO_MAC2) + str(len(TO_MAC2)) + "\n")
                        open(self.resultlog, "a+b").write("DTYPE  : " + str(DTYPE) + "\n")
                        open(self.resultlog, "a+b").write("DTYPE2  : " + str(DTYPE2) + "\n")
                        open(self.resultlog, "a+b").write("DTYPE3  : " + str(DTYPE3) + "\n")
                        open(self.resultlog, "a+b").write("WPS1  : " + str(WPS1) + "\n")
                        open(self.resultlog, "a+b").write("WPS2  : " + str(WPS2) + "\n")
                        open(self.resultlog, "a+b").write("WPS3  : " + str(WPS3) + "\n")
                        open(self.resultlog, "a+b").write("SSID  : " + str(SSID) + "\n")
                        open(self.resultlog, "a+b").write("PSSID : " + str(PSSID) + "\n")
                        open(self.resultlog, "a+b").write("AESSID: " + str(AESSID) + "\n")
                        open(self.resultlog, "a+b").write(
                            "-----------------------------------------------------" + "\n")

                        GET_DATA = "0"
                        GET_AUTH = "0"
                        GET_DEAUTH = "0"
                        GET_DISASSOC = "0"
                        GET_REASSOC = "0"
                        GET_ASSOC = "0"
                        GET_RTS = "0"
                        GET_CTS = "0"
                        GET_ACK = "0"
                        GET_EAPOL = "0"
                        GET_WPS = "0"
                        GET_BEACON = "0"
                        GET_PRESP = "0"
                        GET_PRQX = "0"
                        GET_NULL = "0"
                        GET_QOS = "0"
                        GET_DATA86 = "0"
                        GET_DATA98 = "0"
                        GET_DATA94 = "0"

                        if STYPE == "DATA" or STYPE == "QOS":
                            if TO_MAC1 == "FF:FF:FF:FF:FF:FF":
                                GET_DATA = "1"

                        if STYPE == "DATA":
                            if DTYPE2 == "71" or DTYPE2 == "73":
                                if TO_MAC1[:9] == "01:00:5E:":
                                    GET_DATA = "1"
                            if DTYPE2 == "98" and WPS2 == ".P....F.C":
                                GET_DATA98 = "1"
                            if DTYPE == "94" and WPS2 == ".P...M.T.C":
                                GET_DAYA94 = "1"
                            if WPS2 == ".P.....TC":
                                if FR_MAC[9:] == ":00:00:00":
                                    GET_DATA86 = "1"
                            if TO_MAC1[:9] == "FF:F3:18:":
                                GET_DATA = "1"

                        if STYPE == "QOS":
                            if WPS3 == ".P....F.C" or WPS2 == ".P....F.C":
                                GET_QOS = "1"

                        if STYPE == "AUTHENTICATION":
                            GET_AUTH = "1"
                        if STYPE == "DEAUTHENTICATION":
                            GET_DEAUTH = "1"
                        if STYPE == "DISASSOCIATE":
                            GET_DISASSOC = "1"
                        if STYPE == "ASSOCIATION":
                            GET_ASSOC = "1"
                        if STYPE == "REASSOCIATION":
                            GET_REASSOC = "1"
                        if STYPE == "REQUEST-TO-SEND":
                            GET_RTS = "1"
                        if STYPE == "CLEAR-TO-SEND":
                            GET_CTS = "1"
                        if STYPE == "ACKNOWLEDGEMENT":
                            GET_ACK = "1"
                        if STYPE == "BEACON FRAME":
                            GET_BEACON = "1"
                            open(self.essidfile, "a+b").write("")
                        if STYPE == "EAPOL":
                            GET_EAPOL = "1"
                        if STYPE == "WPS":
                            GET_WPS = "1"
                        if STYPE == "PROBE RESPONSE":
                            GET_PRESP = "1"
                        if STYPE == "PROBE REQUEST":
                            GET_PRQX = "1"
                        if STYPE == "NULL FUNCTION":
                            GET_NULL = "1"

                        if STYPE == "DATA" or STYPE == "QOS" or STYPE == "AUTHENTICATION" or STYPE == "DEAUTHENTICATION" or \
                                        STYPE == "ASSOCIATION" or STYPE == "DISASSOCIATE" or STYPE == "REASSOCIATION" or \
                                        STYPE == "REQUEST-TO-SEND" or STYPE == "CLEAR-TO-SEND" or STYPE == "ACKNOWLEDGEMENT" or \
                                        STYPE == "EAPOL" or STYPE == "WPS" or STYPE == "BEACON FRAME" or STYPE == "PROBE RESPONSE" or \
                                        STYPE == "PROBE REQUEST" or STYPE == "NULL FUNCTION":
                            ListSR = 0
                            ExistList = -1
                            ListLen = len(self.L_FrMAC)
                            if ListLen != 0:
                                while ListSR < ListLen:
                                    if len(FR_MAC) == 17 and len(TO_MAC1) == 17:
                                        if self.L_FrMAC[ListSR] == FR_MAC and self.L_ToMAC[ListSR].find(TO_MAC1) != -1:
                                            ExistList = ListSR

                                        if self.L_FrMAC[ListSR] == FR_MAC and self.L_ToMAC[ListSR].find(
                                                TO_MAC1) == -1 and ExistList == -1:
                                            self.L_ToMAC[ListSR] = self.L_ToMAC[ListSR] + " / " + str(TO_MAC1)
                                            ExistList = ListSR

                                    if len(FR_MAC) == 0 and len(TO_MAC1) == 17 and ExistList == -1:
                                        if self.L_FrMAC[ListSR] == TO_MAC1:
                                            ExistList = ListSR

                                    if ExistList != -1:
                                        ListSR = ListLen
                                    ListSR += 1

                            if ExistList == -1 and len(FR_MAC) == 17:
                                self.L_FrMAC.append(str(FR_MAC))
                                self.L_ToMAC.append(str(TO_MAC1))
                                self.L_Data.append(str(GET_DATA))
                                self.L_Data86.append(str(GET_DATA86))
                                self.L_Data94.append(str(GET_DATA94))
                                self.L_Data98.append(str(GET_DATA98))
                                self.L_Auth.append(str(GET_AUTH))
                                self.L_Deauth.append(str(GET_DEAUTH))
                                self.L_Assoc.append(str(GET_ASSOC))
                                self.L_Reassoc.append(str(GET_REASSOC))
                                self.L_Disassoc.append(str(GET_DISASSOC))
                                self.L_RTS.append(str(GET_RTS))
                                self.L_CTS.append(str(GET_CTS))
                                self.L_ACK.append(str(GET_ACK))
                                self.L_EAPOL.append(str(GET_EAPOL))
                                self.L_WPS.append(str(GET_WPS))
                                self.L_NULL.append(str(GET_NULL))
                                self.L_QOS.append(str(GET_QOS))
                                self.L_Beacon.append(str(GET_BEACON))
                                self.L_PResp.append(str(GET_PRESP))
                                self.L_PReq.append(str(GET_PRQX))
                                self.L_SSID.append(str(SSID) + ", ")
                                self.L_ProbeName.append(str(PSSID) + ", ")

                                if AESSID != "":
                                    self.L_IsAP.append("YES")
                                else:
                                    self.L_IsAP.append("NO")
                            if ExistList != -1:
                                GET_DATA = self.L_Data[ExistList]
                                GET_DATA86 = self.L_Data86[ExistList]
                                GET_DATA94 = self.L_Data94[ExistList]
                                GET_DATA98 = self.L_Data98[ExistList]
                                GET_AUTH = self.L_Auth[ExistList]
                                GET_DEAUTH = self.L_Deauth[ExistList]
                                GET_ASSOC = self.L_Assoc[ExistList]
                                GET_REASSOC = self.L_Reassoc[ExistList]
                                GET_DISASSOC = self.L_Disassoc[ExistList]
                                GET_RTS = self.L_RTS[ExistList]
                                GET_CTS = self.L_CTS[ExistList]
                                GET_ACK = self.L_ACK[ExistList]
                                GET_EAPOL = self.L_EAPOL[ExistList]
                                GET_WPS = self.L_WPS[ExistList]
                                GET_BEACON = self.L_Beacon[ExistList]
                                GET_PRESP = self.L_PResp[ExistList]
                                GET_PRXQ = self.L_PReq[ExistList]
                                GET_NULL = self.L_NULL[ExistList]
                                GET_QOS = self.L_QOS[ExistList]

                                SSID_List = []
                                if self.L_SSID[ExistList] != "":
                                    tmp_ssid = str(self.L_SSID[ExistList])
                                    SSID_List = tmp_ssid.split(", ")

                                Probe_List = []
                                if self.L_ProbeName[ExistList] != "":
                                    tmp_probe = str(self.L_ProbeName[ExistList])
                                    Probe_List = tmp_probe.split(", ")

                                if SSID != "":
                                    self.L_IsAP[ExistList] = "YES"

                                lSSID = len(self.L_SSID)
                                lsid = 0
                                FoundSSID = "0"
                                if lSSID != 0 and SSID != "":
                                    while lsid < lSSID:
                                        if self.L_SSID[lsid] != "" and self.L_SSID[lsid] == str(SSID):
                                            FoundSSID = "1"
                                            lsid = lSSID
                                        lsid += 1
                                    if FoundSSID == "0":
                                        if self.L_SSID[ExistList] == ", ":
                                            self.L_SSID[ExistList] = ""
                                        if SSID != "Broadcast":
                                            self.L_SSID[ExistList] = self.L_SSID[ExistList] + str(SSID) + ", "

                                lSSID = len(self.L_ProbeName)
                                lsid = 0
                                FoundProbeName = "0"
                                if lSSID != 0 and PSSID != "":
                                    while lsid < lSSID:
                                        if self.L_ProbeName[lsid] != "" and self.L_ProbeName[lsid] == str(PSSID):
                                            FoundProbeName = "1"
                                            lsid = lSSID
                                        lsid += 1
                                    if FoundProbeName == "0":
                                        if self.L_ProbeName[ExistList] == ", ":
                                            self.L_ProbeName[ExistList] = ""
                                        self.L_ProbeName[ExistList] = self.L_ProbeName[ExistList] + str(
                                            PSSID) + ", "
                                if STYPE == "DATA" and DTYPE2 == "98" and WPS2 == ".P....F.C":
                                    GET_DATA98 = str(int(GET_DATA98) + 1)

                                if STYPE == "DATA" and DTYPE == "98" and WPS2 == ".P.....TC":
                                    GET_DATA98 = str(int(GET_DATA98) + 1)

                                if STYPE == "DATA" and DTYPE2 == "94" and WPS2 == ".P...M.TC":
                                    GET_DATA94 = str(int(GET_DATA94) + 1)

                                if STYPE == "DATA" or STYPE == "QOS":
                                    if TO_MAC1 == "FF:FF:FF:FF:FF:FF":
                                        GET_DATA = str(int(GET_DATA) + 1)
                                if STYPE == "DATA":
                                    if DTYPE2 == "71" or DTYPE2 == "73":
                                        if TO_MAC1[:9] == "01:00:5E:":
                                            GET_DATA = str(int(GET_DATA) + 1)
                                if STYPE == "DATA":
                                    if TO_MAC1[:9] != "FF:FF:FF:" and TO_MAC1[:3] == "FF:":
                                        GET_DATA = str(int(GET_DATA) + 1)

                                if STYPE == "DATA" and WPS2 == ".P.....TC":
                                    if FR_MAC[9:] == "00:00:00":
                                        GET_DATA86 = str(int(GET_DATA86) + 1)

                                if STYPE == "AUTHENTICATION":
                                    GET_AUTH = str(int(GET_AUTH) + 1)
                                if STYPE == "DEAUTHENTICATION":
                                    GET_DEAUTH = str(int(GET_DEAUTH) + 1)
                                if STYPE == "DISASSOCIATE":
                                    GET_DISASSOC = str(int(GET_DISASSOC) + 1)
                                if STYPE == "ASSOCIATION":
                                    GET_ASSOC = str(int(GET_ASSOC) + 1)
                                if STYPE == "REASSOCIATION":
                                    GET_REASSOC = str(int(GET_REASSOC) + 1)
                                if STYPE == "REQUEST-TO-SEND":
                                    GET_RTS = str(int(GET_RTS) + 1)
                                if STYPE == "CLEAR-TO-SEND":
                                    GET_CTS = str(int(GET_CTS) + 1)
                                if STYPE == "ACKNOWLEDGEMENT":
                                    GET_ACK = str(int(GET_ACK) + 1)
                                if STYPE == "EAPOL":
                                    GET_EAPOL = str(int(GET_EAPOL) + 1)
                                if STYPE == "WPS":
                                    GET_WPS = str(int(GET_WPS) + 1)
                                if STYPE == "BEACON FRAME":
                                    GET_BEACON = str(int(GET_BEACON) + 1)
                                if STYPE == "PROBE RESPONSE":
                                    GET_PRESP = str(int(GET_PRESP) + 1)
                                if STYPE == "PROBE REQUEST":
                                    GET_PRQX = str(int(GET_PRQX) + 1)
                                if STYPE == "NULL FUNCTION":
                                    GET_NULL = str(int(GET_NULL) + 1)
                                if STYPE == "QOS" and TO_MAC1[:9] != "FF:FF:FF:":
                                    if WPS3 == ".P....F.C" or WPS2 == ".P....F.C":
                                        GET_QOS = str(int(GET_QOS) + 1)

                                self.L_Data[ExistList] = GET_DATA
                                self.L_Data86[ExistList] = GET_DATA86
                                self.L_Data94[ExistList] = GET_DATA94
                                self.L_Data98[ExistList] = GET_DATA98
                                self.L_Auth[ExistList] = GET_AUTH
                                self.L_Deauth[ExistList] = GET_DEAUTH
                                self.L_Assoc[ExistList] = GET_ASSOC
                                self.L_Reassoc[ExistList] = GET_REASSOC
                                self.L_Disassoc[ExistList] = GET_DISASSOC
                                self.L_RTS[ExistList] = GET_RTS
                                self.L_CTS[ExistList] = GET_CTS
                                self.L_ACK[ExistList] = GET_ACK
                                self.L_EAPOL[ExistList] = GET_ACK
                                self.L_WPS[ExistList] = GET_WPS
                                self.L_Beacon[ExistList] = GET_BEACON
                                self.L_PResp[ExistList] = GET_PRESP
                                self.L_PReq[ExistList] = GET_PRQX
                                self.L_NULL[ExistList] = GET_NULL
                                self.L_QOS[ExistList] = GET_QOS

                                if SSID != "" and self.L_SSID[ExistList] == "":
                                    self.L_SSID[ExistList] = SSID + ", "
                                    self.L_IsAP[ExistList] = "Yes"
                                if PSSID != "" and self.L_ProbeName[ExistList] == "":
                                    self.L_ProbeName[ExistList] = PSSID + ", "
                                if AESSID != "":
                                    self.L_IsAP[ExistList] = "Yes"
                x = 0
                while x < len(self.L_FrMAC):
                    SSID_CT = "0"
                    if self.L_SSID[x] != "":
                        if self.L_SSID[x][-2:] == ", ":
                            self.L_SSID[x] = self.L_SSID[x][:-2]
                            self.L_SSID[x] = self.L_SSID[x].replace("Broadcast, ", "").replace("Broadcast", "")
                            SSID_List = self.L_SSID[x].split(", ")
                            SSID_CT = str(len(SSID_List))
                    if self.L_ProbeName[x] != "":
                        if self.L_ProbeName[x][-2:] == ", ":
                            self.L_ProbeName[x] = self.L_ProbeName[x][:-2]
                            if self.L_ProbeName[x] != "" and self.L_SSID[x] != "":
                                if self.L_Beacon == 0:
                                    self.L_SSID[x] = ""
                                    self.L_IsAP[x] = "No"
                    if self.L_SSID[x] == "":
                        SSID_CT = "0"

                    self.L_SSIDCT.append(str(SSID_CT))
                    x += 1
                if os.path.isfile(self.resultlist):
                    open(self.resultlist, "wb").write("" + "\n")
                time_stamp = datetime.datetime.fromtimestamp((time.time())).strftime('%Y-%m-%d %H:%M:%S')
                open(self.resultlist, "wb").write(self.tcpdump_log + "\n")
                open(self.resultlist, "a+b").write("Date Time \t" + str(time_stamp) + "\n")
                x = 0
                l = len(self.L_FrMAC)
                while x < l:
                    open(self.resultlist, "a+b").write(
                        "SN\tFR MAC \t\t\tBF   \tIsAP? \tECT  \tData \tData86 \tDat94  \tDat98 \tQOS\tAuth "
                        "\tDeauth \tAssoc \tR.Asc \tD.Asc \tRTS \tCTS \tACK \tEAPOL \tWPS \tRQX \tResp \tNULL"
                        "\n")
                    open(self.resultlist, "a+b").write(str(x) + "\t" + self.L_FrMAC[x] + "\t" + self.L_Beacon[x] + "\t" +
                                                       self.L_IsAP[x] + "\t" + self.L_SSIDCT[x] + "\t" + self.L_Data[
                        x] + "\t" +
                                                       self.L_Data86[x] + "\t" + self.L_Data94[x] + "\t" + self.L_Data98[
                        x] + "\t"
                                                       + self.L_QOS[x] + "\t" + self.L_Auth[x] + "\t" + self.L_Deauth[
                                                           x] + "\t" +
                                                       self.L_Assoc[x] + "\t" + self.L_Reassoc[x] + "\t" + self.L_Disassoc[
                                                           x] +
                                                       "\t" + self.L_RTS[x] + "\t" + self.L_CTS[x] + "\t" + self.L_ACK[
                                                           x] + "\t"
                                                       + self.L_EAPOL[x] + "\t" + self.L_WPS[x] + "\t" + self.L_PReq[
                                                           x] + "\t"
                                                       + self.L_PResp[x] + "\t" + self.L_NULL[x] + "\n")
                    open(self.resultlist, "a+b").write("ESSID\t" + self.L_SSID[x] + "\n")
                    open(self.resultlist, "a+b").write("Probe\t" + self.L_ProbeName[x] + "\n")
                    open(self.resultlist, "a+b").write("DEST\t" + self.L_ToMAC[x] + "\n\n")
                    x += 1
                open(self.resultlist, "a+b").write("" + "\n\n")

                listlen = len(self.L_FrMAC)
                listsr = 0
                Concern = 0
                AWPA = 0
                AWEP = 0
                AWPS = 0
                ATUN = 0
                AWNG = 0
                ACCP = 0
                ATFL = 0
                ABCF = 0
                MDKM = 0
                ASFL = 0
                PGRA = 0
                IARP = 0
                WPAD = 0
                WPSDetected = 0
                AType = ""
                recent_result = "["
                Write_Result = ""
                if listlen != 0:
                    while listsr < listlen:
                        TOMAC = self.L_ToMAC[listsr]
                        TOMACLIST = TOMAC.split(" / ")
                        tml = 0
                        Multicast = 0
                        Chopchop = 0
                        while tml < len(TOMACLIST):
                            ChkMAC = TOMACLIST[tml]
                            if ChkMAC[:9] == "01:00:5E:":
                                Multicast += 1
                            if ChkMAC[:0] != "FF:FF:FF:" and ChkMAC[:3] == "FF:":
                                Chopchop += 1
                            tml += 1

                        if int(self.L_Deauth[listsr]) >= 10:
                            FrMAC = str(self.L_FrMAC[listsr])
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if ToMAC == "":
                                ToMAC = "Broadcast"

                            if int(self.L_Disassoc[listsr]) >= 10:
                                Concern += 1
                                AType = "DISASSOC"
                                WPAD = "1"
                                Write_Result += '{"attack": "Disassocation Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "MDK3 WPA Downgrade", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Disassocation Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "MDK3 WPA Downgrade", "Time": "' + time_stamp + '"}, '
                            else:
                                Concern += 1
                                AType = "DEAUTH"
                                ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                                GenPrivacy = ReturnResult.split(",")[0].lstrip().rstrip()
                                if FrMAC == "00:00:00:00:00:00" or ToMAC == "00:00:00:00:00:00":
                                    ATUN = "1"
                                    Write_Result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "TKIPTUN-NG Signature", "Time": "' + time_stamp + '"}, '
                                    recent_result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "TKIPTUN-NG Signature", "Time": "' + time_stamp + '"}, '
                                elif str(GenPrivacy) == "WPA" or int(self.L_EAPOL[listsr]) > 0:
                                    AWPA = "1"
                                Write_Result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "None", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "None", "Time": "' + time_stamp + '"}, '
                        else:
                            if int(self.L_Deauth[listsr]) > 0:
                                FrMAC = str(self.L_FrMAC[listsr])
                                ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                                if self.L_FrMAC[listsr].find("00:00:00:00:00:00") != -1 or self.L_ToMAC[listsr].find(
                                        "00:00:00:00:00:00") != -1:
                                    Concern += 1
                                    AType = "DEAUTH"
                                    ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                                    GenPrivacy = ReturnResult.split(",")[0]
                                    ATUN = "1"
                                    Write_Result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "TKIPTUN-NG Signature", "Time": "' + time_stamp + '"}, '
                                    recent_result += '{"attack": "Deauth Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "TKIPTUN-NG Signature", "Time": "' + time_stamp + '"}, '

                        if int(self.L_Data[listsr]) >= 25:
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if ToMAC == "":
                                ToMAC = "Broadcast"
                            if int(self.L_Data[listsr]) > 30 and Multicast <= 1 and Chopchop <= 1:
                                Concern += 1
                                AType = "BCDATA"
                                ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                                GenPrivacy = ReturnResult.split(",")[0].lstrip().rstrip()
                                if str(GenPrivacy) == "WEP":
                                    AWEP = "1"

                            if Multicast > 5:
                                Concern += 1
                                AType = "BCDATA"
                                ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                                AWNG = "1"
                                if str(GenPrivacy) == "WEP":
                                    AWEP = "1"
                                Write_Result += '{"attack": "Wessid-NG Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Wesside-NG", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Wessid-NG Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Wesside-NG", "Time": "' + time_stamp + '"}, '

                            if Chopchop > 5:
                                Concern += 1
                                AType = "BCDATA"
                                ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                                GenPrivacy = ReturnResult.split(",")[0].lstrip().rstrip()
                                ACCP = "1"
                                if str(GenPrivacy) == "WEP":
                                    AWEP = "1"
                                Write_Result += '{"attack": "Korek ChopChop Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Korek CopChop", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Korek ChopChop Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Korek CopChop", "Time": "' + time_stamp + '"}, '

                        if int(self.L_Data94[listsr]) >= 5:
                            Concern += 1
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if ToMAC == "":
                                ToMAC = "Broadcast"
                            AType = "PRGA"
                            PRGA = "1"
                            ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                            GenPrivacy = ReturnResult.split(",")[0].lstrip().rstrip()
                            if str(GenPrivacy) == "WEP":
                                AWEP = "1"
                            Write_Result += '{"attack": "Fragmentation PRGA Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                            '", "Possible": "Fragmentation PRGA", "Time": "' + time_stamp + '"}, '
                            recent_result += '{"attack": "Fragmentation PRGA Attack", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                            '", "Possible": "Fragmentation PRGA", "Time": "' + time_stamp + '"}, '

                        if int(self.L_Data86[listsr]) >= 5:
                            Concern += 1
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if ToMAC == "":
                                ToMAC = "Broadcast"
                            AType = "MDKM"
                            MDKM = "1"
                            Write_Result += '{"attack": "MDK Micheal shutdown Exploitation (TKIP)", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                            '", "Possible": "MDK Micheal", "Time": "' + time_stamp + '"}, '
                            recent_result += '{"attack": "MDK Micheal shutdown Exploitation (TKIP)", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                            '", "Possible": "MDK Micheal", "Time": "' + time_stamp + '"}, '

                        if int(self.L_QOS[listsr]) >= 1:
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if ToMAC == "":
                                ToMAC = "Broadcast"
                            ReturnResult = self.GetMACDetail(FrMAC, ToMAC)
                            Cipher = ReturnResult.split(",")[1].lstrip().rstrip()
                            if Cipher == "TKIP":
                                AType = "TUN"
                                ATUN = "1"
                                Concern += 1
                                Write_Result += '{"attack": "Attack by TKIPTUN-NG", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Basing on Signature", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Attack by TKIPTUN-NG", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Basing on Signature", "Time": "' + time_stamp + '"}, '

                        if int(self.L_Auth[listsr]) >= 5:
                            Concern += 1
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if int(self.L_Auth[listsr]) <= 80:
                                AType = "AUTH"
                            else:
                                if len(self.L_ToMAC[listsr]) > 100:
                                    ATFL = "1"
                                    AType = "AUTH"
                                    Write_Result += '{"attack": "Authentication DOS", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "Aireplay-NG WPA Migration Mode", "Time": "' + time_stamp + '"}, '
                                    recent_result += '{"attack": "Authentication DOS", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "Aireplay-NG WPA Migration Mode", "Time": "' + time_stamp + '"}, '
                                else:
                                    ATFL = "1"
                                    AType = "AUTH"
                                    Write_Result += '{"attack": "Authentication DOS", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "Unusual high amount sent Authentication", "Time": "' + time_stamp + '"}, '
                                    recent_result += '{"attack": "Authentication DOS", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                    '", "Possible": "Unusual high amount sent Authentication", "Time": "' + time_stamp + '"}, '

                        if int(self.L_Assoc[listsr]) >= 8:
                            Concern += 1
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            if len(self.L_ToMAC[listsr]) > 100:
                                ASFL = "1"
                                AType = "ASSOC"
                                Write_Result += '{"attack": "Association Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + self.L_Assoc[listsr] + \
                                                '", "Possible": "Possible", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Association Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + self.L_Assoc[listsr] + \
                                                '", "Possible": "Possible", "Time": "' + time_stamp + '"}, '
                            else:
                                AType = "ASSOC"
                                Write_Result += '{"attack": "High amount of association sent", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "likely to be Association Flood", "Time": "' + time_stamp + '"}, '

                        if int(self.L_WPS[listsr]) >= 2:
                            Concern += 1
                            WPSDetected = 1
                            AWPS = "1"
                            FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                            ToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                            AType = "EAP"


                        if int(self.L_SSIDCT[listsr]) >= 2:
                            FrMAC = str(self.L_FrMAC[listsr])
                            ToMAC = str(self.L_ToMAC[listsr])
                            if ToMAC != "FF:FF:FF:FF:FF" or len(ToMAC) > 17:
                                TMC = []
                                AList = self.L_SSID[listsr] + ", "
                                TMC = AList.split(",")
                                FM = "0"
                                if self.L_SSIDCT[listsr] == "2" or self.L_SSIDCT[listsr] == "3":
                                    if self.L_SSIDCT[listsr] == "3":
                                        try:
                                            if len(TMC[0].lstrip().rstrip()) == len(TMC[1].lstrip().rstrip()) and len(
                                                    TMC[1].lstrip().rstrip()) == len(TMC[2].lstrip().rstrip()):
                                                FM = "1"
                                        except IndexError:
                                            pass
                                    else:
                                        if len(TMC[0].lstrip().rstrip()) == len(TMC[1].lstrip().rstrip()):
                                            FM = "1"
                                if FM == "0":
                                    AToMAC = ToMAC
                                    if AToMAC == "FF:FF:FF:FF:FF:FF":
                                        AToMAC = "Broadcast"
                                    else:
                                        FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                                        AToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                                    SSIDCount = self.L_SSIDCT[listsr]
                                    if self.L_SSID[listsr].find("Broadcast") != -1 and AToMAC != "":
                                        SSIDCount = int(SSIDCount) - 1
                                    FrMAC = self.RemoveUnwantMAC(str(self.L_FrMAC[listsr]))
                                    AToMAC = self.RemoveUnwantMAC(str(self.L_ToMAC[listsr]))
                                    Concern += 1
                                    RAPDected = 1
                                    ARPA = "1"
                                    AType = "RAP"
                                    # Write_Result += '{"attack": "Suspect Rouge AP", "src_mac": "' + FrMAC + '", "dst_mac": "' + AToMAC + \
                                    #                '", "Possible": "Broadcasted SSID Name [' + self.L_SSID[listsr] + \
                                    #                ']", "Time": "' + time_stamp + '"}, '

                            if ToMAC == "FF:FF:FF:FF:FF:FF" and int(self.L_SSIDCT[listsr]) > 15:
                                Concern += 1
                                ATYPE = "BCF"
                                ABCF = "1"
                                Write_Result += '{"attack": "Detected Beacon Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Broadcasted SSID Name [' + self.L_SSID[listsr] + \
                                                ']", "Time": "' + time_stamp + '"}, '
                                recent_result += '{"attack": "Detected Beacon Flood", "src_mac": "' + FrMAC + '", "dst_mac": "' + ToMAC + \
                                                '", "Possible": "Broadcasted SSID Name [' + self.L_SSID[listsr] + \
                                                ']", "Time": "' + time_stamp + '"}, '
                        listsr += 1

                recent_result += "]"
                open(self.recent_logfile, 'w').write(recent_result)
                Write_Result = "[" + open(self.json_logfile, 'r').read().replace("[", "").replace("]", "") + Write_Result + "]"
                open(self.json_logfile, 'w').write(Write_Result)
                Result = ""
                if Concern == 0:
                    if os.path.isfile(self.tcpdump_cap):
                        if os.stat(self.tcpdump_cap).st_size >= 300:
                            Result = ('Did not detect any suspicious activity \n')
                else:
                    Result = time_stamp + " - " + " concerns found...\n"
                    WText = ""
                    if AWEP == "1":
                        WText = str(WText) + "WEP , "
                    if AWNG == "1":
                        WText = str(WText) + "WESSID-NG , "
                    if ACCP == "1":
                        WText = str(WText) + "Korek ChopChop , "
                    if AWPA == "1":
                        WText = str(WText) + "WPA , "
                    if ATUN == "1":
                        WText = str(WText) + "TKPUN-NG , "
                    if AWPS == "1":
                        WText = str(WText) + "WPS , "
                    if ATFL == "1":
                        WText = str(WText) + "Authentication DOS , "
                    if ASFL == "1":
                        WText = str(WText) + "Association DOS , "
                    if ABCF == "1":
                        WText = str(WText) + "Beacon Flood ,"
                    if PGRA == "1":
                        WText = str(WText) + "Fragmentation PRGA , "
                    if IARP == "1":
                        WText = str(WText) + "ARP/Interactive Reply , "
                    if MDKM == "1":
                        WText = str(WText) + "MDK3 - Michael Shutdown Exploitation , "
                    if WPAD == "1":
                        WText = str(WText) + "MDK3 - WPA Downgrade Test , "
                    if WText != "":
                        WText = WText[:-3]
                        Result = Result + "\n      Possibility : " + WText + " attacks."

                if Result != "":
                    open(self.logfile, "a+b").write(Result + '\n')
                    if Concern != 0:
                        open(self.logfile, "a+b").write('\n')

    def GetEncType(self, AFMAC):
        Privacy = ""
        if os.path.isfile(self.captured_csv):
            CLIENTS = ""
            with open(self.captured_csv, "r") as f:
                for line in f:
                    if len(line) > 10 and line.find(str(AFMAC)) != -1 and CLIENTS != 1:
                        line = line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., "
                        line = line.replace("\r", "")
                        CList = line.split(",")
                        Privacy = CList[5].lstrip().rstrip()
                        Privacy = Privacy.replace('WPA2WPA OPN', 'WPA2WPA (OPN)')
                        Privacy = Privacy.replace('WPA2 OPN', 'WPA2 (OPN)')
                        Privacy = Privacy.replace('WPA OPN', 'WPA (OPN)')
                        Privacy = Privacy.replace('WPA2WPA', 'WPA2/WPA')
                        Privacy = Privacy.replace('WEP OPN', 'WEP (OPN)')
                        CLIENTS = 1
        return Privacy

    def GetMACDetail(self, FrMAC, ToMAC):
        Privacy = ""
        PrivacyBK = ""
        Cipher = ""
        CipherBK = ""
        Authentication = ""
        AuthenticationBK = ""
        CLIENTS = 0
        if os.path.isfile(self.captured_csv):
            with open(self.captured_csv, "r") as f:
                for line in f:
                    if len(line) > 10:
                        line = line + " ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., ., "
                        line = line.replace("\r", "")
                        CList = line.split(",")
                        FMAC = line.split()[0].replace(',', '')
                        FS1 = line.split()[0].replace(',', '')
                        FS2 = line.split()[1].replace(',', '')
                        FS = str(FS1) + " " + str(FS2)
                        Privacy = CList[5].lstrip().rstrip()
                        Cipher = CList[6].lstrip().rstrip()
                        Authentication = CList[7].lstrip().rstrip()
                        ESSID = CList[13].lstrip().rstrip().replace("\n", "")
                        Privacy = Privacy.replace('WPA2WPA OPN', 'WPA2WPA (OPN)')
                        Privacy = Privacy.replace('WPA2 OPN', 'WPA2 (OPN)')
                        Privacy = Privacy.replace('WPA OPN', 'WPA (OPN)')
                        Privacy = Privacy.replace('WPA2WPA', 'WPA2/WPA')
                        Privacy = Privacy.replace('WEP OPN', 'WEP (OPN)')
                        Cipher = Cipher.replace('CCMP TKIP', 'CCMP/TKIP')

                        if FS == "Station MAC":
                            CLIENTS = 1
                            if FrMAC.find(str(FMAC)) != -1:
                                if CLIENTS != 1 and Privacy != "":
                                    if ESSID == "":
                                        ESSID = "<<NO ESSID>>"
                                    CAMC = "1"
                                    PrivacyBK = Privacy
                                    CipherBK = Cipher
                                    AuthenticationBK = Authentication

                        if ToMAC.find(str(FMAC)) != -1:
                            if CLIENTS != 1:
                                PrivacyBK = Privacy
                                CipherBK = Cipher
                                AuthenticationBK = Authentication

        if len(Privacy) == 17:
            Privacy = self.GetEncType(Privacy)
            PrivacyBK = Privacy
        else:
            if Privacy == "" or Privacy == "(not associated)":
                Privacy = self.GetEncType(Privacy)
                PrivacyBK = Privacy

        PrivacyBK = PrivacyBK.lstrip().rstrip()
        CipherBK = CipherBK.lstrip().rstrip()
        AuthenticationBK = AuthenticationBK.lstrip().rstrip()
        PrivacyGeneral = ""
        if PrivacyBK != "" and PrivacyBK.find("WPA") != -1:
            if PrivacyBK.find("WEP") != -1:
                if CipherBK.find("WEP") != -1:
                    PrivacyGeneral = "WEP"
                else:
                    PrivacyGeneral = "WPA"
            else:
                PrivacyGeneral = "WPA"
        else:
            PrivacyGeneral = PrivacyBK
        PrivacyGeneral = PrivacyGeneral.lstrip().rstrip()
        return PrivacyGeneral + ", " + str(PrivacyBK) + ", " + str(CipherBK) + ", " + str(AuthenticationBK)

    def GetESSID(self, MAC_ADDR):
        ESSID = ""
        if os.path.isfile(self.essidlog):
            if len(MAC_ADDR) == 17:
                with open(self.essidlog, "r") as rf:
                    for eline in rf:
                        eline = eline.replace("\n", "")
                        if len(eline) >= 18:
                            if eline.find(MAC_ADDR) != -1:
                                ESSID = eline.replace(MAC_ADDR + "\t", "")
                                if ESSID != "(not associated)":
                                    return ESSID

    def stop(self):
        Popen("killall tshark", shell=True, stdout=None, stderr=None)
        self.START_SIG = False

    def get_recent_values(self):
        values = open(self.recent_logfile, 'r').read()
        open(self.recent_logfile, 'w').write("")
        return values

    def get_values(self):
        return open(self.json_logfile, 'r').read()

    @staticmethod
    def RemoveUnwantMAC(MACAddr):
        sMAC = MACAddr.split("/")
        x = 0
        lsMAC = len(sMAC)
        while x < lsMAC:
            MAC_ADR = sMAC[x]
            MAC_ADR = MAC_ADR.lstrip().rstrip()
            sMAC[x] = MAC_ADR
            if MAC_ADR[:12] == "FF:FF:FF:FF:":
                sMAC[x] = ""
            if MAC_ADR[:6] == "33:33:":
                sMAC[x] = ""
            if MAC_ADR[:9] == "01:80:C2:":
                sMAC[x] = ""
            if MAC_ADR[:9] == "01:00:5E:":
                sMAC[x] = ""
            if MAC_ADR[:3] == "FF:":
                sMAC[x] = ""
            if MAC_ADR == "":
                sMAC[x] = ""
            x += 1
        x = 0
        NewMAC = ""
        while x < len(sMAC):
            if sMAC[x] != "":
                NewMAC = NewMAC + str(sMAC[x]) + " / "
            x += 1
        if NewMAC[-3:] == " / ":
            NewMAC = NewMAC[:-3]
        return NewMAC

"""
import threading
# from module.wids import Wireless_IDS
wids = Wireless_IDS('atear_wids')
wids_process = threading.Thread(target=wids.run)
wids_process.start()
while True:
    try:
        print 'Recent Log: ', wids.get_recent_values()
        print 'All Log: ', wids.get_values()
        time.sleep(20)
    except KeyboardInterrupt:
        wids.stop()
"""