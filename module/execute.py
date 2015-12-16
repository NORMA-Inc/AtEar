from subprocess import Popen, PIPE


def execute(command, wait=True):
    if wait == True:
        proc = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        retval = proc.returncode
    else: # wait == False
        _dn = open('/dev/null','wb')
        proc = Popen(command, stdout=_dn, stderr=_dn)
        retval = 1
        out = None
        err = None
    return proc, retval, out, err

