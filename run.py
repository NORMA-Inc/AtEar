# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, Response
import json
import time
from module import airodump
from module.fake_ap import APCreate
import pickle
from module.wids import Wireless_IDS
from module.pentest_open import auto_pentest
from multiprocessing import Process
import ast
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class PythonObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}


def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct


class main_app():
    def __init__(self):
        self.app = Flask(__name__)
        self.run = False
        self.scanner = False
        self.fake_ap = False
        self.pentesting = False
        self.scan_iface = 'atear_dump'
        self.pent_iface = 'atear_pentest'
        self.ap_iface = 'atear_ap'
        self.app.add_url_rule('/', 'index', self.index)
        self.app.add_url_rule('/tpl/<name>', 'load_tpl', self.load_tpl)
        self.app.add_url_rule('/app', 'app_view', self.app_view)
        self.app.add_url_rule('/api/scanstatus', 'scanstatus', self.scanstatus, methods=['POST', 'GET'])
        self.app.add_url_rule('/api/fakeap', 'fakeap', self.fakeap, methods=['POST', 'GET', 'DELETE'])
        self.app.add_url_rule('/api/wids', 'wids', self.wids, methods=['GET'])
        self.app.add_url_rule('/api/pentest', 'pentest', self.pentest, methods=['GET', 'POST'])
        self.app.add_url_rule('/api/hidden/<wids_option>', 'hidden', self.hidden, methods=['GET'])
        self.app.run('0.0.0.0', port=8080, debug=False)

    def index(self):
        return render_template('main.html')

    def load_tpl(self, name):
        return render_template(name+'.html')

    def app_view(self):
        return render_template('index.html')

    def scanstatus(self):
        if request.method == 'GET':
            if not self.scanner:
                self.scanner = airodump.Scanner(self.scan_iface)
                self.scanner.run()
                time.sleep(2)
                return "[]", 200
            else:
                try:
                    return Response(json.dumps(self.scanner.get_value(), cls=PythonObjectEncoder, ensure_ascii=False),
                                    mimetype='application/json')
                except:
                    return "[]", 200
        elif request.method == 'POST':
            self.scanner.stop()
            self.scanner = False
            return '', 200
        return '', 200

    def fakeap(self):
        if request.method == 'POST':
            options = request.get_json()
            self.fake_ap = APCreate(self.ap_iface, options['enc'], options['ssid'], options['password'])
            self.fake_ap.run()
            return '', 200
        elif request.method == 'GET':
            if self.fake_ap:
                try:
                    connstation = self.fake_ap.get_values_connect()
                    connstation = connstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
                    loginstation = self.fake_ap.get_values_login()
                    loginstation = loginstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
                    return json.dumps({"connstation": connstation, "loginstation": loginstation})
                except:
                    return json.dumps({"connstation": '', "loginstation": ''})
            else:
                return json.dumps({"connstation": '', "loginstation": ''})
        elif request.method == 'DELETE':
            self.fake_ap.stop()
            self.fake_ap = False
            return '', 200
        return '', 200

    def wids(self):
        if request.method == 'GET':
            try:
                return_value = ast.literal_eval(wids.get_values())
                return json.dumps(return_value)
            except:
                return json.dumps([{}])

    def pentest(self):
        if request.method == 'POST':
            options = request.get_json()
            self.pentesting = auto_pentest(self.pent_iface, options)
            self.pentesting.run()

            return '', 200

        elif request.method == 'GET':
            try:
                return_values = ast.literal_eval(self.pentesting.get_values())
                return json.dumps(return_values)
            except:
                return json.dumps([{}])
        return '', 200

    def hidden(self, wids_option):
        if request.method == 'GET':
            if wids_option == '1':
                recent_val = wids.get_recent_values()
                try:
                    recent_val = ast.literal_eval(recent_val)
                    return json.dumps({"message": recent_val})
                except:
                    return json.dumps({"message": []})
            elif wids_option == '0':
                wids.stop()
                return json.dumps({"message": []})
        return '', 200


if __name__ == '__main__':
    from module.network import auto_monitor, stop_monitor
    try:
        stop_monitor()
        auto_monitor()
        wids = Wireless_IDS('atear_wids')
        wids_process = Process(target=wids.run)
        wids_process.start()
        main_app()
    # Stop Signal
    except KeyboardInterrupt:
        stop_monitor()
        wids_process.terminate()