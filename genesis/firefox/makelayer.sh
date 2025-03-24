cd $(dirname $0)
mydir=$(pwd)
cd -
cd /
tar -czvhf /tmp/firefox.tgz usr/bin/firefox usr/lib64/firefox $(cat $mydir/firefoxlibs)
cd -
