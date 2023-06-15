pushd $(dirname $0)
rm -rf licenses
cp -a 97genesis /usr/lib/dracut/modules.d/
cat /usr/lib/dracut/modules.d/97genesis/install-* > /usr/lib/dracut/modules.d/97genesis/install
chmod +x /usr/lib/dracut/modules.d/97genesis/install /usr/lib/dracut/modules.d/97genesis/installkernel
mkdir -p boot/initramfs
mkdir -p boot/efi/boot
dracut --no-early-microcode --xz -N -m "genesis base" -f boot/initramfs/distribution $(uname -r)
tdir=$(mktemp -d)
tfile=$(mktemp)
cp boot/initramfs/distribution $tdir
pushd $tdir
xzcat distribution|cpio -dumi
rm distribution
find . -type f -exec rpm -qf /{} \; 2> /dev/null | grep -v 'not owned' | sort -u > $tfile
find . -type f -printf "%p: " -exec rpm -qf /{} \; 2> /dev/null | grep -v 'not owned' > /tmp/attributedrpmlist
popd
rm -rf $tdir
cp $tfile rpmlist
cp confluent-genesis.spec confluent-genesis-out.spec
python3 getlicenses.py rpmlist > /tmp/tmpliclist
if [ $? -ne 0 ]; then
    exit 1
fi
for lic in $(cat /tmp/tmpliclist); do
    lo=${lic#/usr/share/}
    lo=${lo#licenses/}
    lo=${lo#doc/}
    fname=$(basename $lo)
    dlo=$(dirname $lo)
    if [[ "$dlo" == *"-lib"* ]]; then
        dlo=${dlo/-*}
    elif [[ "$dlo" == "device-mapper-"* ]]; then
	dlo=${dlo/-*}-mapper
    elif [[ "$dlo" == "bind-"* ]]; then
	dlo=${dlo/-*}
    elif [[ "$dlo" == "iproute-"* ]]; then
	dlo=${dlo/-*}
    fi
    mkdir -p licenses/$dlo
    if [ "$fname" == "lgpl-2.1.txt" ]; then
	fname=COPYING.LIB
    fi
    cp $lic licenses/$dlo/$fname
    lo=$dlo/$fname
    echo %license /opt/confluent/genesis/%{arch}/licenses/$lo >> confluent-genesis-out.spec
done
mkdir -p licenses/ipmitool
cp /usr/share/doc/ipmitool/COPYING  licenses/ipmitool
echo %license /opt/confluent/genesis/%{arch}/licenses/ipmitool/COPYING >> confluent-genesis-out.spec
ln -s /opt/confluent/genesis/%{arch}/licenses/kernel-core licenses/libbpf
echo /opt/confluent/genesis/%{arch}/licenses/libbpf >> confluent-genesis-out.spec
cp -f /boot/vmlinuz-$(uname -r) boot/kernel
cp /boot/efi/EFI/BOOT/BOOTX64.EFI boot/efi/boot
find /boot/efi -name grubx64.efi -exec cp {} boot/efi/boot/grubx64.efi \;
mkdir -p ~/rpmbuild/SOURCES/
tar cf ~/rpmbuild/SOURCES/confluent-genesis.tar boot rpmlist licenses
rpmbuild -bb confluent-genesis-out.spec
rm -rf /usr/lib/dracut/modules.d/97genesis
popd
# for rpm in $(cat ../rpmlist); do dnf download --source $rpm; done
# getting src rpms would be nice, but centos isn't consistent..
# /usr/lib/dracut/skipcpio /opt/confluent/genesis/x86_64/boot/initramfs/distribution | xzcat | cpio -dumiv
# rpm -qf $(find . -type f | sed -e 's/^.//') |sort -u|grep -v 'not owned' > ../rpmlist
# for f in $(find . -type f | sed -e 's/^.//'); do echo -n $f:; rpm -qf $f ; done > ../annotedrprmlist
# for i in $(cat rpmlist); do rpm -qi $i|grep Source; done |awk '{print $4}'|sort -u > srcrpmlist
# for i in $(cat ../srcrpmlist); do wget --continue http://vault.centos.org/8.2.2004/BaseOS/Source/SPackages/$i; done
# ls > downloadedsrcpmlist
# diff -u srcpmlist downloadedsrcrpmlist
# diff -u srcrpmlist downloadedsrcpmrlist |grep ^-|grep -v srcrpmlist
# for i in $(diff -u srcrpmlist downloadedsrcpmrlist |grep ^-|grep -v srcrpmlist|sed -e s/-//); do wget --continue http://vault.centos.org/8.2.2004/AppStream/Source/SPackages/$i; done



