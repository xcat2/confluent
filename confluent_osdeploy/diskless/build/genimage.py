import optparse
import os
import subprocess
import tempfile
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


def create_yumconf(sourcedir):
    hdl, name = tempfile.mkstemp(prefix='genimage-yumconfig.')
    yumconf = os.fdopen(hdl, mode='w+')
    if os.path.exists(sourcedir + '/repodata'):
        pass
    else:
        c = configparser.ConfigParser()
        c.read(sourcedir + '/.treeinfo')
        for sec in c.sections():
            if sec.startswith('variant-'):
                try:
                    repopath = c.get(sec, 'repository')
                except Exception:
                    continue
                _, varname = sec.split('-', 1)
                yumconf.write('[genimage-{0}]\n'.format(varname.lower()))
                yumconf.write('name=Local install repository for {0}\n'.format(varname))
                currdir = os.path.join(sourcedir, repopath)
                yumconf.write('baseurl={0}\n'.format(currdir))
                yumconf.write('enabled=1\ngpgcheck=0\n\n')
    return name


def main():
    parser = optparse.OptionParser()
    parser.add_option('-s', '--source', help='Directory to pull installation from (e.g. /var/lib/confluent/distributions/rocky-8.3-x86_64')
    (opts, args) = parser.parse_args()
    yumargs = ['yum', '--installroot={0}'.format(args[0])]
    if opts.source:
        yumconfig = create_yumconf(opts.source)
        yumargs.extend(['-c', yumconfig, '--disablerepo=*', '--enablerepo=genimage-*'])
    yumargs.append('install')
    with open(os.path.join(os.path.dirname(__file__), 'pkglist'), 'r') as pkglist:
        pkgs = pkglist.read()
        pkgs = pkgs.split()
        yumargs.extend(pkgs)
    subprocess.check_call(yumargs)

if __name__ == '__main__':
    main()
