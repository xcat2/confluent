Name: confluent_deploy-x86_64
Version: 3.0
Release 1%{?dist}
Summary: OS Deployment support for confluent

License: Apache2
URL: http://hpc.lenovo.com/
Source0: confluent-deploy.tar.xz
BulidArch: noarch
Requires: confluent_ipxe
BuildRoot: /tmp

%description
This contains support utilities for enabling deployment of x86_64 architecture systems


%define debug_package %{nil}

%prep
%setup

%build
mkdir -p opt/confluent/bin
cd utils
make all
cp copernicus clortho autocons ../opt/confluent/bin
cd ..
mkdir el8out suse15out ubuntu20.04out
cd el8out
cp -a ../opt .
mkdir -p usr/lib/dracut/hooks/
cp -a ../el8/dracut-hooks/* usr/lib/dracut/hooks/
find . | cpio -H newc > addons.cpio
cd ../suse15out
cp -a ../opt .
cp -a ../suse15/opt ../suse15/etc .
find . | cpio -H newc > addons.cpio
cd ../ubuntu20.04out
cp -a ../opt .
cp -a ../ubuntu20.04/initramfs/* .
find . | cpio -H newc > addons.cpio

%install
pwd
ls



