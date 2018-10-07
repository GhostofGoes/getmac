%global srcname getmac

Name:           python2-%{srcname}
Version:        0.5
Release:        0%{?dist}
Summary:        Python module to get the MAC address of local network interfaces and LAN hosts(edited)

License:        MIT
URL:            https://github.com/GhostofGoes/get-mac
Source0:        https://github.com/GhostofGoes/get-mac/releases/download/0.5.0/get-mac-0.5.0.tar.gz

BuildArch:      noarch
BuildRequires:  python2-devel

%description
Pure-python module to get the MAC address of remote hosts or network interfaces. It provides a platform-independent interface to get the MAC addresses of network interfaces on the local system(by interface name) and remote hosts on the local network (by IPv4/IPv6 address or hostname).

%{?python_provide:%python_provide python3-getmac}

%prep
%autosetup -n %{srcname}-%{version}

%build
%py2_build

%install
%py2_install
%files
%license LICENSE
%doc README.md
%{python2_sitelib}/%{srcname}/
%{python2_sitelib}/%{srcname}-*.egg-info/
/usr/bin/%{srcname}

%changelog