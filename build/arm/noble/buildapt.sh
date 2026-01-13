#cp -a /sources/git /tmp
for builder in $(find /sources/git -name builddeb); do
    cd $(dirname $builder)
    ./builddeb /debs/
done
cp /prebuilt/* /debs/
cp /osd/*.deb /debs/
mkdir -p /apt/conf/
CODENAME=$(grep VERSION_CODENAME= /etc/os-release | sed -e 's/.*=//')
if [ -z "$CODENAME" ]; then
    CODENAME=$(grep VERSION= /etc/os-release | sed -e 's/.*(//' -e 's/).*//')
fi
if ! grep $CODENAME /apt/conf/distributions; then
    sed -e s/#CODENAME#/$CODENAME/ /bin/distributions.tmpl >> /apt/conf/distributions
fi
cd /apt/
reprepro includedeb $CODENAME /debs/*.deb
for dsc in /debs/*.dsc; do
    reprepro includedsc $CODENAME $dsc
done

