from subprocess import Popen, PIPE


def execute(command):
    p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
    out = p.stdout.read()
    err = p.stderr.read()
    retval = p.wait()
    return retval, out, err