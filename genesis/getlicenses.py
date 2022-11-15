import subprocess
import sys
import shlex

def runcmd(cmd):
    return subprocess.check_output(shlex.split(cmd)).decode('utf8').split('\n')

def getsrpm(rpm):
    rpminfo = runcmd(f'rpm -qi {rpm}')
    for inf in rpminfo:
        if inf.startswith('Source RPM'):
            srpm = inf.split(':', 1)[1].strip()
            return srpm

srpmtorpm = {}
rpmtosrpm = {}
allrpmlist = runcmd('rpm -qa')
for rpm in allrpmlist:
    if not rpm:
        continue
    srpm = getsrpm(rpm)
    rpmtosrpm[rpm] = srpm
    if srpm in srpmtorpm:
        srpmtorpm[srpm].add(rpm)
    else:
        srpmtorpm[srpm] = {rpm}

with open(sys.argv[1]) as rpmlist:
    rpmlist = rpmlist.read().split('\n')
licenses = set([])
for rpm in rpmlist:
    if not rpm:
        continue
    srpm = rpmtosrpm[rpm]
    if srpm.startswith('linux-firmware'):
        continue
    for relrpm in srpmtorpm[srpm]:
        liclist = runcmd(f'rpm -qL {relrpm}')
        for lic in liclist:
            if lic == '(contains no files)':
                continue
            licenses.add(lic)
for lic in sorted(licenses):
    print(lic)

            

