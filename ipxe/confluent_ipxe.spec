Name: confluent_ipxe
Version: 2.0.0
Release: 2
Summary: iPXE network boot roms for confluent

License: GPL
Source: https://github.com/ipxe/ipxe/releases/latest/download/ipxeboot.tar.gz
Obsoletes: confluent_ipxe-aarch64 < 2.0.0
Provides: confluent_ipxe-aarch64 = %{version}-%{release}
BuildArch: noarch

%description
iPXE boot roms for chainloading systems

%define debug_package %{nil}
%prep
%setup -n ipxeboot


%install
mkdir -p %{buildroot}/opt/confluent/lib/ipxe
cp x86_64/undionly.kpxe %{buildroot}/opt/confluent/lib/ipxe/ipxe.kkpxe
cp x86_64-sb/shimx64.efi %{buildroot}/opt/confluent/lib/ipxe/ipxe-shim.efi
cp x86_64-sb/snponly.efi %{buildroot}/opt/confluent/lib/ipxe/ipxe.efi
cp arm64-sb/shimaa64.efi %{buildroot}/opt/confluent/lib/ipxe/ipxe-aarch64-shim.efi
cp arm64-sb/snponly.efi %{buildroot}/opt/confluent/lib/ipxe/ipxe-aarch64.efi

%files
/opt/confluent/lib/ipxe/ipxe.kkpxe
/opt/confluent/lib/ipxe/ipxe.efi
/opt/confluent/lib/ipxe/ipxe-shim.efi
/opt/confluent/lib/ipxe/ipxe-aarch64-shim.efi
/opt/confluent/lib/ipxe/ipxe-aarch64.efi

%post
# UEFI HTTP boot chainloads the shim from the public tree. A fresh install
# leaves it to osdeploy initialize, so public keeps the ownership the
# server gives it.
if [ -d /var/lib/confluent/public ]; then
    mkdir -p /var/lib/confluent/public/ipxe/x86_64 /var/lib/confluent/public/ipxe/aarch64
    cp /opt/confluent/lib/ipxe/ipxe-shim.efi /opt/confluent/lib/ipxe/ipxe.efi /var/lib/confluent/public/ipxe/x86_64/
    cp /opt/confluent/lib/ipxe/ipxe-aarch64-shim.efi /var/lib/confluent/public/ipxe/aarch64/ipxe-shim.efi
    cp /opt/confluent/lib/ipxe/ipxe-aarch64.efi /var/lib/confluent/public/ipxe/aarch64/ipxe.efi
fi
true


%changelog
* Tue Sep 22 2026 Confluent <hpchelp@lenovo.com> - 2.0.0-1
- Initial
