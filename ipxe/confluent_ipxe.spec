Name: confluent_ipxe
Version: 2.0.0
Release: 1
Summary: iPXE network boot roms for confluent

License: GPL
Source: https://github.com/ipxe/ipxe/releases/latest/download/ipxeboot.tar.gz
Obsoletes: confluent_ipxe-aarch64 < 2.0.0
Provides: confluent_ipxe-aarch64 = %{version}-%{release}
BuildArch: noarch

%description
iPXE boot roms for chainloading systems

%define debug_pagkage %{nil}
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




%changelog
* Tue Sep 22 2026 Confluent <hpchelp@lenovo.com> - 2.0.0-1
- Initial
[jjohnson2@fourge ~]$ cat ~/rpmbuild/SPECS/confluent_ipxe.spec 
Name: confluent_ipxe
Version: 2.0.0
Release: 1
Summary: iPXE network boot roms for confluent

License: GPL
Source: https://github.com/ipxe/ipxe/releases/latest/download/ipxeboot.tar.gz
Obsoletes: confluent_ipxe-aarch64 < 2.0.0
Provides: confluent_ipxe-aarch64 = %{version}-%{release}
BuildArch: noarch

%description
iPXE boot roms for chainloading systems

%define debug_pagkage %{nil}
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




%changelog
* Tue Sep 22 2026 Confluent <hpchelp@lenovo.com> - 2.0.0-1
- Initial

