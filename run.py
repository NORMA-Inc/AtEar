# -*- coding: utf-8 -*-
__author__ = 'NORMA_ATEAR'
from flask import Flask, request, g,render_template, Response, redirect, url_for, session,jsonify
from functools import wraps
import json
import os
from sqlite.sqlite_query_lib import sqlite_query_lib
from module import airodump
from module.fake_ap import APCreate
import pickle
from module.wids import Wireless_IDS
import threading
import ast


class PythonObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}


def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct


app = Flask(__name__)
global run
run = False
global scanner
scanner = False
DATABASE = 'sqlite/atear.db'
app.secret_key = 'atear_norma_key'
app.config.from_object(__name__)


@app.before_request
def before_request():
    if not hasattr(g, 'db'):
        g.db = sqlite_query_lib()
        g.db.open(DATABASE)


@app.teardown_request
def teardown_request(exception):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login',next=request.url))
        try:
            return f(*args, **kwargs)
        except:
            return decorated_function
    return decorated_function


@app.route('/')
def index():
    return redirect(url_for('app_view'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == "POST":
        if request.form['username'] and request.form['password']:
            login_result = g.db.select_user(request.form['username'],request.form['password'])
            if login_result == 0:
                return render_template('login.html',error='Invalid Username')
            elif login_result == 1:
                session['logged_in'] = True
                session['username'] = request.form['username']
                return redirect(url_for('app_view'))
            else:
                return render_template('login.html',error='Invalid password')
        else:
            return render_template('login.html', error='Please Input username & password')


@app.route('/logout')
def logout():
    session['logged_in'] = False
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/tpl/<name>')
def load_tpl(name):
    return render_template(name+'.html')


@app.route('/project')
@login_required
def app_view():
    return render_template('index.html', username=session['username'])


@app.route('/api/projects', methods=['DELETE', 'GET', 'PUT', 'POST'])
@app.route('/api/projects/<project_id>', methods=['DELETE', 'GET', 'PUT'])
@login_required
def project_api(project_id=None):
    if project_id:
        if request.method =='DELETE':
            cursor = g.db.delete_project(project_id)

        elif request.method =='GET':
            json_result = g.db.select_project(session['username'],project_id)

            return json_result
        elif request.method =='POST':
            project = request.get_json()
            p_name = project['p_name']
            p_desc = project['p_desc']
            p_time = project['p_time']

            json_result = g.db.insert_project(session['username'],p_name,p_desc,p_time)
            return json_result
        elif request.method =='PUT':
            project = request.get_json()
            p_id = project['id']
            p_name = project['p_name']
            p_desc = project['p_desc']
            p_time = project['p_time']

            json_result = g.db.update_project(p_id,p_name,p_desc,p_time)
            return json_result
    else:
        if request.method == 'GET':
            json_result = g.db.select_project(session['username'])

            return json_result
        elif request.method == 'POST':
            project = request.get_json()
            p_name = project['p_name']
            p_desc = project['p_desc']
            p_time = project['p_time']
            json_result = g.db.insert_project(session['username'], p_name, p_desc, p_time)
            return json_result
    return '', 200

@app.route('/api/scanstatus/<project_id>', methods=['POST', 'GET'])
@app.route('/api/scanstatus/<project_id>/<cell_name>', methods=['POST'])
@login_required
def scanstatus(project_id=None, cell_name=None):
    global scanner
    if cell_name:
        if request.method == 'POST':
            if scanner:
                print 'STOP IN'
                scanner.stop()
                scanner = False
            c_id = g.db.insert_cell(cell_name, project_id)
            scandatas = request.get_json()
            datas = []
            for d in scandatas:
                data = (d['bssid'], d['type'], d['company'], d['essid'], d['ch'], d['enc'], d['nb_data'], d['nb_beacons']
                        , d['power'], d['product'], d['clients'], d['sid-length'], c_id)
                datas.append(data)
            g.db.insert_scan_data(datas)
            return '', 200
    else:
        if request.method =='GET':
            print 'GET IN'
            if not scanner:
                scanner = airodump.Scanner('wlan0')
                scanner.run()
            try:
                return Response(json.dumps(scanner.get_value(), cls=PythonObjectEncoder), mimetype='application/json')
            except:
                return '', 200
        elif request.method == 'POST':
            print 'STOP IN'
            scanner.stop()
            scanner = False
            return '', 200
    return '', 200


@app.route('/api/fakeap', methods=['POST', 'GET', 'DELETE'])
@login_required
def fakeap():
    global fake_ap
    if request.method == 'POST':
        options = request.get_json()
        fake_ap = APCreate('wlan0', options['enc'], options['ssid'], options['password'])
        fake_ap.run()
        return '', 200
    elif request.method == 'GET':
        if fake_ap:
            try:
                connstation = fake_ap.get_values_connect()
                connstation = connstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
                loginstation = fake_ap.get_values_login()
                loginstation = loginstation.replace('\\', '').replace('\"', '').replace(', ]', ']')
            except:
                return json.dumps({"connstation:": '', "loginstation": ''})
        return json.dumps({"connstation": connstation, "loginstation": loginstation})
    elif request.method == 'DELETE':
        fake_ap.stop()
        fake_ap = False
        return '', 200
    return '', 200


@app.route('/api/wids', methods=['GET'])
@login_required
def wids():
    if request.method == 'GET':
        try:
            return_value = ast.literal_eval(wids.get_values())
            return json.dumps(return_value)
        except:
            return json.dumps([{}])


@app.route('/api/hidden/<wids_option>', methods=['GET'])
@login_required
def hidden(wids_option):
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
    if not os.path.isfile(DATABASE):
        from sqlite import install
        install.create_database(DATABASE)
        print 'Database Created'
    wids = Wireless_IDS('wlan0')
    wids_process = threading.Thread(target=wids.run)
    wids_process.start()
    app.run(host='0.0.0.0', debug=True, port=8090)