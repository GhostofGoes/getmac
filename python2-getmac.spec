%global srcname getmac

Name:           python2-%{srcname}
Version:        0.6.0
Release:        0
Summary:        Python module to get the MAC address of local network interfaces and LAN hosts

License:        MIT
URL:            https://github.com/GhostofGoes/getmac
Source0:        https://github.com/GhostofGoes/getmac/releases/download/0.6.0/getmac-0.6.0.tar.gz

BuildArch:      noarch
BuildRequires:  python2-devel

%description
Pure-python module to get the MAC address of remote hosts or network interfaces.
It provides a platform-independent interface to get the MAC addresses of network
interfaces on the local system(by interface name) and remote hosts on the local
network (by IPv4/IPv6 address or host name).

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
/usr/bin/getmac2
%{_mandir}/man1/*

%changelog
* Sat Oct 6 2018 Christopher Goes <ghostofgoes@gmail.com> 0.6.0-0
- Windows default interface detection if `network_request` is enabled (Credit: @cyberhobbes)
- Docker container (Credit: @Komish)
- Changed name to `getmac`. This applies to everything, including
command line tool, PyPI, GitHub, and the documentation.
This is a breaking change, but needed to happen to remove
a huge amount of ambiguity that was causing issues with packaging,
documentation, and several other efforts, not to mention my sanity.
Long-term, the only downside is a conflict on Windows CLI with `getmac.exe`.
- Use proper Python 2-compatible print functions (Credit: @martmists)
- Support for Python 2.5. It is not feasible to test, and potentially
breaks some useful language features, such as `__future__`
- Variables PORT and DEBUG from top-level package imports, since changing
them would have no actual effect on execution. Instead, use `getmac.getmac.DEBUG`.
- Added example videos demonstrating usage (Credit: @fortunate-man)
- Added contribution guide
- Added documentation on ReadTheDocs
- Added a manpage

* Mon Sep 24 2018 Christopher Goes <ghostofgoes@gmail.com> 0.5-0
- Full support for Windows Subsystem for Linux (WSL). This is working for
all features, including default interface selection! The only edge case
is lookup of remote host IP addresses that are actually local interfaces
won't resolve to a MAC (which should be ff-ff-ff-ff-ff-ff).
- Require `argparse` if Python version is 2.6 or older
- Updated tox tests: added Jython and IronPython, removed 2.6

* Fri Sep 21 2018 Christopher Goes <ghostofgoes@gmail.com> 0.4-0
- New methods for remote host MACs
- New methods for interface MACs
- DEBUG levels: DEBUG value is now an integer, and increasing it will
increase the amount and verbosity of output. On the CLI, it can be
configured by increasing the amount of characters for the debug argument,
e.g. '-dd' for DEBUG level 2.
- Jython support (Note: on Windows Jython currently only works with interfaces)
- IronPython support
- Significant performance improvement for remote hosts. Previously,
the average for `get_mac_address(ip='10.0.0.100')` was 1.71 seconds.
Now, the average is `12.7 miliseconds`, with the special case of a unpopulated
arp table being only slightly higher. This was brought about by changes in
how the arp table is populated. The original method was to use the
host's `ping` command to send an ICMP packet to the host. This took time,
which heavily delayed the ability to actually get an address. The solution
is to instead simply send a empty UDP packet to a high port. The port
this packet is sent to can be configured using the module variable `getmac.PORT`.
- "Fixed" resolution of localhost/127.0.0.1 by hardcoding the response.
This should resolve a lot of problematic edge cases. I'm ok with this
for now since I don't know of a case when it isn't all zeroes.
- Greatly increased the reliability of getting host and interface MACs on Windows
- Improved debugging output
- Tightened up the size of `getmac.py`
- Various minor stability and performance improvements
- Add LICENSE to PyPI package
- Support for Python 3.2 and 3.3. The total downloads from PyPI with
those versions in August was ~53k and ~407K, respectfully. The majority
of those are likely from automated testing (e.g. TravisCI) and not
actual users. Therefore, I've decided to drop support to simplify
development, especially since before 3.4 the 3.x series was still
very much a  "work in progress".
- Added automated tests for Windows using Appveyor
- Tox runner for tests
- Added github.io page
- Improved TravisCI testing

* Thu Aug 30 2018 Christopher Goes <ghostofgoes@gmail.com> 0.3-0
- Attempt to use Python modules if they're installed. This is useful
for larger projects that already have them installed as dependencies,
as they provide a more reliable means of getting information.
- New methods for remote MACs
- New methods for Interface MACs
- Certain critical failures that should never happen will now warn
instead of failing silently.
- Added a sanity check to the `ip6` argument (IPv6 addresses)
- Improved performance in some areas
- Improved debugging output
- Major Bugfix: search of `proc/net/arp` would return shorter addresses in the
same subnet if they came earlier in the sequence. Example: a search for
`192.168.16.2` on Linux would instead return the MAC address of
`192.168.16.254` with no errors or warning whatsoever.
- Significantly improved default interface detection. Default
interfaces are now properly detected on Linux and most other
POSIX platforms with `ip` or `route` commands available, or the
`netifaces` Python module.
- Makefile
- Vagrantfile to spin up testing VMs for various platforms using [Vagrant](https://www.vagrantup.com/docs/)
- Added more samples of command output on platforms (Ubuntu 18.04 LTS)

* Sun Aug 26 2018 Christopher Goes <ghostofgoes@gmail.com> 0.2-4
- Fixed identification of remote host on OSX
- Resolved hangs and noticeable lag that occurred when "network_request"
was True (the default)


* Tue Aug 7 2018 Christopher Goes <ghostofgoes@gmail.com> 0.2-3
- Remote host for Python 3 on Windows

* Wed Apr 18 2018 Christopher Goes <ghostofgoes@gmail.com> 0.2-2
- Short versions of CLI arguments (e.g. "-i" for "--interface")
- Improved usage of "ping" across platforms and IP versions
- Various minor tweaks for performance
- Improved Windows detection
- Use of ping command with hostname
- Improvements to internal code


* Sun Apr 15 2018 Christopher Goes <ghostofgoes@gmail.com> 0.2-1
- Nothing changed. PyPI just won't let me push changes without a new version.

* Sun Apr 15 2018 Christopher Goes <ghostofgoes@gmail.com> 0.2-0
- Checks for default interface on Linux systems
- New methods of hunting for addresses on Windows, Mac OS X, and Linux
- CLI will output nothing if it failed, instead of "None"
- CLI will return with 1 on failure, 0 on success
- No CLI arguments now implies the default host network interface
- Added an argumnent for debugging: `--debug`
- Removed `-d` option from `--no-network-requests`
- Interfaces on Windows and Linux (including Bash for Windows)
- Many bugs
- Support for Python 2.6 on the CLI
- Overhaul of internals


* Sun Apr 15 2018 Christopher Goes <ghostofgoes@gmail.com> 0.1-0:
- Addition of a terminal command: `get-mac`
- Ability to run as a module from the command line: `python -m getmac`
- `arp_request` argument was renamed to `network_request`
- Updated docstring
- Slight reduction in the size of getmac.py
- Overhauled the README
- Moved tests into their own folder
- Added Python 3.7 to list of supported snakes


* Sun Nov 12 2017 Christopher Goes <ghostofgoes@gmail.com> 0.0-4:
- Python 2.6 compatibility


* Sat Nov 11 2017 Christopher Goes <ghostofgoes@gmail.com> 0.0-3:
- Fixed some addresses returning without colons
- Added more rigorous checks on addresses before returning them


* Sat Nov 11 2017 Christopher Goes <ghostofgoes@gmail.com> 0.0-2:
- Remove print statements and other debugging output


* Mon Oct 23 2017 Christopher Goes <ghostofgoes@gmail.com> 0.0-1
- Initial pre-alpha
