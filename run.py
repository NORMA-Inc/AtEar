# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, Response
import json
from module import airodump
from module.fake_ap import APCreate
import pickle
from module.wids import Wireless_IDS
from module.pentest_open import auto_pentest
from multiprocessing import Process
import ast
import sys
import time, os
from module.execute import execute
from module.network import *
reload(sys)
sys.setdefaultencoding('utf-8')


class PythonObjectEncoder(json.JSONEncoder):
    ''' @brief Encoder for hangul(Korean).
        @param obj:
        *    json.JSONEncoder
    '''
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}


def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct


class main_app():
    '''
        @brief Flask module for interact with user.
    '''
    def __init__(self, interface):
        '''
            @brief Create flask-server module and run.
            * Set running config.
            * Run server 0.0.0.0:8080
        '''
        self.app = Flask(__name__)
        self.run = False
        self.wids_handle = False
        self.scanner = None
        self.fake_ap = None
        self.pentesting = None
        self.scan_iface = interface
        self.app.add_url_rule('/', 'index', self.index)
        self.app.add_url_rule('/tpl/<name>', 'load_tpl', self.load_tpl)
        self.app.add_url_rule('/app', 'app_view', self.app_view)
        self.app.add_url_rule('/api/scanstatus', 'scanstatus', self.scanstatus, methods=['POST', 'GET'])
        self.app.add_url_rule('/api/fakeap', 'fakeap', self.fakeap, methods=['POST', 'GET', 'DELETE'])
        self.app.add_url_rule('/api/wids', 'wids', self.wids, methods=['GET'])
        self.app.add_url_rule('/api/pentest', 'pentest', self.pentest, methods=['GET', 'POST'])
        self.app.add_url_rule('/api/hidden/<wids_option>', 'hidden', self.hidden, methods=['GET'])
        execute('fuser -k -n tcp 8080') # If port 8080 is in use, close it.
        self.app.run('0.0.0.0', port=8080, debug=False)

    def index(self):
        ''' Render main.html '''
        return render_template('main.html')

    def load_tpl(self, name):
        return render_template(name+'.html')

    def app_view(self):
        ''' Render index.html '''
        return render_template('index.html')

    def scanstatus(self):
        ''' It responds to the airodump-scan results. '''
        # 먼저 진행 중이던 작업을 취소.
        #print self.scanner, self.pentesting, self.fake_ap, self.wids_handle
        if self.pentesting:
            self.pentesting.stop()
            self.pentesting = None

        if self.fake_ap:
            self.fake_ap.stop()
            self.fake_ap = None

        if request.method == 'GET':
            if not self.scanner:

                # Class Atear-Beta.module.airodump  line 106.
                self.scanner = airodump.Scanner(self.scan_iface)
                self.scanner.run()

                # class  	AtEar-Beta.module.wids.Wireless_IDS
                # Prepare a file to store the results.
                print "[*] START AtEar-WIDS"
                wids = Wireless_IDS(self.scan_iface)

                # def AtEar-Beta.module.wids.Wireless_IDS.run(self) line 78
                # Generate wids.run to child process.
                wids.start()
                self.wids_handle=True
                print "[*] START AtEar-UI"

                return "[]", 200

            else:
                try:
                    # Return the scan results.
                    return Response(json.dumps(self.scanner.get_value(), cls=PythonObjectEncoder, ensure_ascii=False,
                                                encoding='EUC-KR'), mimetype='application/json')
                except:
                    return "[]", 200

        elif request.method == 'POST':
            if self.scanner:
                self.scanner.stop()
                self.scanner = None
            return '', 200

        return '', 200

    def fakeap(self):
        '''
            @brief Create fake-AP
        '''
        # 먼저 진행 중이던 작업을 취소.
        if self.wids_handle:
            self.wids_handle.terminate()
            self.wids_handle.join()
            self.wids_handle = None

        if self.scanner:
            self.scanner.stop()
            self.scanner = None

        if self.pentesting:
            self.pentesting.stop()
            self.pentesting = None

        if request.method == 'POST':
            # Create Fake-AP with parameters from user selected.
            if self.fake_ap:
                self.fake_ap.stop()
            monitormode_change(self.scan_iface)
            options = request.get_json()
            self.fake_ap = APCreate(self.self.scan_iface, options['enc'], options['ssid'], options['password'])
            self.fake_ap.run()

        elif request.method == 'GET':
            if self.fake_ap:
                try:
                    # Load the collected device information.
                    connstation = self.fake_ap.get_values_connect()
                    connstation = connstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
                    # Load the collected user login information.
                    loginstation = self.fake_ap.get_values_login()
                    loginstation = loginstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
                    return json.dumps({"connstation": connstation, "loginstation": loginstation})
                except:
                    return json.dumps({"connstation": '', "loginstation": ''})
            else:
                return json.dumps({"connstation": '', "loginstation": ''})

        elif request.method == 'DELETE':
            # Stop fake_AP
            if self.fake_ap:
                self.fake_ap.stop()
            self.fake_ap = None

        return '', 200

    def wids(self):
        '''
            @brief Return the collected information from wids module.
        '''
        # 먼저 진행 중이던 작업을 취소.
        if self.pentesting:
            self.pentesting.stop()
            self.pentesting = None

        if self.scanner:
            self.scanner.stop()
            self.scanner = None

        if self.fake_ap:
            self.fake_ap.stop()
            self.fake_ap = None

        if not self.wids_handle:
            self.wids_handle = Wireless_IDS('atear_wids')
            self.wids_handle.start()
        if request.method == 'GET':
            try:
                return_value = ast.literal_eval(self.wids_handle.get_values())
                return json.dumps(return_value, ensure_ascii=False, encoding='EUC-KR')
            except:
                return json.dumps([{}])


    def pentest(self):
        '''
            @brief Allowing access to pentest function.
            * POST  - Perform the pentest.
            * GET   - Return the result of pentest.
        '''
        # 먼저 진행 중이던 작업을 취소.
        if self.wids_handle:
            self.wids_handle.terminate()
            self.wids_handle.join()
            self.wids_handle = None

        if self.scanner:
            self.scanner.stop()
            self.scanner = None

        if self.fake_ap:
            self.fake_ap.stop()
            self.fake_ap = None

        if request.method == 'POST':
            if self.pentesting:
                self.pentesting.stop()
            options = request.get_json()
            self.pentesting = auto_pentest(self.self.scan_iface, options)
            self.pentesting.run()
            return '', 200

        elif request.method == 'GET':
            try:
                return_values = self.pentesting.get_values()
                return json.dumps(return_values, ensure_ascii=False, encoding='EUC-KR')
            except:
                return json.dumps([{}])
        return '', 200


    def hidden(self, wids_option):
        '''
            @brief Return the result of the most recent attacks or not.
            @param wids_option:
            *   1 - Return the result of the most recent attacks.
            *   0 - Return empty message.
        '''
        if request.method == 'GET':
            if wids_option == '1':
                recent_val = self.wids_handle.get_recent_values()
                try:
                    recent_val = ast.literal_eval(recent_val)
                    return json.dumps({"message": recent_val}, ensure_ascii=False, encoding='EUC-KR')
                except:
                    return json.dumps({"message": []})
            elif wids_option == '0': # alive reserve
                return json.dumps({"message": []})
        return '', 200

def shutdown(signum, frame):
    print "\nStopping monitoring mode..."
    monitormode_change(iface, True)
    os.system('fuser -k -n tcp 8080')
    print "Bye"
    sys.exit(1)

if __name__ == '__main__':
    '''
        @brief AtEar main function.
    '''
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--iface", type=str,
                       help="monitoring interface")

    args = parser.parse_args()
    wids_process = False

    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, shutdown)

    print "Start AtEar-Beta...."
    print "Changing Monitoring mode..."
    monitormode_change(args.iface)
    main_app(args.iface)
