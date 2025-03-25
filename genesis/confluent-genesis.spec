%define arch x86_64
Version: 3.13.0
Release:  1
Name: confluent-genesis-%{arch}
BuildArch: noarch
Summary: Genesis servicing image for confluent
Source0: confluent-genesis.tar
URL: https://github.com/lenovo/confluent
AutoReq: false
AutoProv: false
License: Various

%Description
A small linux environment to proved a servicing image to boot systems into if needed.

%prep

%build

%install
mkdir -p $RPM_BUILD_ROOT
cd $RPM_BUILD_ROOT
mkdir -p opt/confluent/genesis/%{arch}
cd opt/confluent/genesis/%{arch}
tar xvf %{SOURCE0}
find . -type d -exec chmod o+rx {} +
find . -type f -exec chmod o+r {} +
find . -type f -exec chmod -x {} +

%files
/opt/confluent/genesis/%{arch}/rpmlist
/opt/confluent/genesis/%{arch}/boot/efi/boot/BOOTX64.EFI
/opt/confluent/genesis/%{arch}/boot/efi/boot/grubx64.efi
/opt/confluent/genesis/%{arch}/boot/initramfs/distribution
/opt/confluent/genesis/%{arch}/boot/kernel
