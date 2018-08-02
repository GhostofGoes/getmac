
# Bugs
* [ ] Interface IP on Ubuntu gets loopback, instead of primary interface

# Features
* [ ] Support for IPv6 hostname resolution
* [ ] make_arp_request
* [ ] Add ability to get the mac address of a socket's interface
* [ ] Improve:
    ip: more methods
    interface: more methods
    make_arp request: method in addition to ping (sockets?)
* [ ] Unicode handling. UNICODE option needed for non-english locales? (Is LC_ALL working?)
* [ ] Test against non-ethernet interfaces (WiFi, LTE, etc.)
* [ ] Threading (spin out all attempts, plus make itself thread-friendly)

## Platform TODO
* [ ] Linux (Debian and RHEL-based)
* [ ] Windows pre-2000
* [ ] Darwin (Mac OS)
* [ ] OpenBSD
* [ ] FreeBSD
* [ ] Android (Which you could argue [correctly] is Linux)
* [ ] Solaris

# Improvements
* [ ] Improve support for IPv6 in general
* [ ] Cache results on regex-heavy functions (add a arg to disable this behavior)
* [ ] Ignore case on MAC regexs?
* [ ] Reduce the size on disk of the source code
* [ ] Improve performance (spend a lot of time on performance tuning with the regexes)

# Dev/project
* [ ] Unit tests for individual methods (monkey patch if needed)
* [ ] Functional tests (to the furthest extent we can)
* [ ] Screenshots
* [ ] ASCII Cinema capture of usage
* [ ] Appveyor testing
* [ ] Sphinx documentation
* [ ] Documentation on ReadTheDocs

# Misc
* [ ] Support everything on this [list](https://www.python.org/dev/peps/pep-0011/#no-longer-supported-platforms).
That is partially in jest, partially insane[ity].
* [ ] Unittesting of Python 2.6 (since we have it disabled on CLI tests)
* [ ] Use optparse instead of argparse?
