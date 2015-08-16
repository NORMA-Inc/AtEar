# -*- coding: utf-8 -*-
__author__ = 'hackpupu'


def brute_text_create(min_length=1, max_length=3, letters=True, numbers=True, symbols=True, spaces=False):
    from string import digits as _numbers, letters as _letters, punctuation as _symbols, whitespace as _spaces
    from itertools import chain, product
    from random import sample
    choices = ''
    choices += _letters if letters else ''
    choices += _numbers if numbers else ''
    choices += _symbols if symbols else ''
    choices += _spaces if spaces else ''
    choices = ''.join(sample(choices, len(choices)))

    return (
        ''.join(candidate) for candidate in
        chain.from_iterable(
            product(
                choices,
                repeat=i,
            ) for i in range(min_length, max_length + 1),
        )
    )



def ftp_connect(username, password, target, port, timeout):
    try:
        from ftplib import FTP
    except Exception, e:
        print "Import Error: " + e
        return False
    try:
        ftp = FTP()
        ftp.connect(host=target, port=port, timeout=int(timeout))
        ftp.login(username, password)
        ftp.retrlines('LIST')
        return username, password
    except Exception, e:
        print "Unknown Error: ", e
        return False


def telnet_connect(username, password, target, port, timeout):
    import socket

    telnet = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    telnet.settimeout(timeout)
    try:
        telnet.connect(target, port)
        telnet_io = telnet.makefile()
    except Exception, e:
        print "Unknwon Error: " + e
        return False


def ssh_connect(username, password, target, port, timeout):
    try:
        from paramiko import SSHClient
        from paramiko import AutoAddPolicy
    except Exception, e:
        print "Import Error" + e
        return False
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(target, port=port, username=username, password=password, timeout=timeout,
                    allow_agent=False, look_for_keys=False)
        return username, password
        ssh.close()
    except Exception, e:
        print "Unknwon Error: " + e
        return False


def smtp_connection(username, password, targetip, port, timeout):
    import smtplib
    try:
        smtpserver = smtplib.SMTP(targetip, port)
        smtpserver.ehlo()
        smtpserver.starttls()
        smtpserver.ehlo()
        smtpserver.login(username,password)
        return {'username':username, 'password':password ,'targetip':targetip, 'port':port }
    except:
        return False


def postgresql(username, password, targetip, port, timeout):
    import psycopg2
    try:
        conn = psycopg2.connect(user=username,password=password,host=targetip,port=port)
        return {'username':username, 'password':password ,'targetip':targetip, 'port':port }
    except:
        return False


def mssql(username, password, targetip, port, timeout):
    import pyodbc
    cnxn = pyodbc.connect('DRIVER={SQL Server};'
                          'SERVER=' + targetip + ';DATABASE=sp_defaultdb;UID=' + username + ';PWD=' + password)
    cursor = cnxn.cursor()
    cursor.execute("select user_id, user_name from users")
    rows = cursor.fetchall()
    for row in rows:
        print row.user_id, row.user_name


def POP(username, password, targetip, port, timeout):
    print 'POP'


def SMB(username, password, targetip, port, timeout):
    from smb.SMBConnection import SMBConnection
    try:
        system_name="server"
        conn = SMBConnection(username,password,"Norma-Atear",targetip,use_ntlm_v2=True,
                            sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
                            is_direct_tcp=True)
        connected = conn.connect(targetip,port)
    except:
        print('### can not access the system')


def oracle_db(username, password, targetip, port, timeout):
    print 'oracl'


for text in brute_text_create(3):
    print text