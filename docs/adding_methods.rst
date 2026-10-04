===================
Adding a new method
===================

getmac finds MAC addresses using *methods*, which are subclasses of :class:`~getmac.getmac.Method` that implement a technique for getting a MAC, such as running a command or reading a file. Supporting a new command, file, or platform means adding a new method.

To use a custom method in your own code without changing getmac, see :doc:`module_api` instead. For setting up a development environment and the rules for pull requests, see :doc:`contributing`.

The examples on this page use a hypothetical ``IpAddrIface`` method, which gets the MAC address of an interface on Linux from the output of ``ip addr show <iface>``. It isn't part of getmac.


Collect sample output
=====================

Method tests run against real command output saved in ``tests/samples/``, so start by capturing output on the platform the method is for. In this context, a "command" would be ``ip addr`` on Linux.

``scripts/collect_samples.py`` runs the commands that getmac uses on the current platform, and saves the output of each one to a file in ``tests/samples/<platform>_<version>/`` (e.g. ``tests/samples/ubuntu_24.04/``). Exit codes and error messages are logged to ``collect_samples.log`` in the same directory. The script only needs Python, so it can be copied to a machine that doesn't have getmac. A copy outside the repo saves to ``./samples/<platform>_<version>/`` instead (or the directory given with ``--output-root``).

.. code-block:: shell

   python scripts/collect_samples.py --dry-run  # list what would be collected
   python scripts/collect_samples.py  # Run the collection

Alternatively, you can run the command by hand and save the output with ``tee``:

.. code-block:: shell

   mkdir -p tests/samples/ubuntu_24.04
   ip addr show ens33 | tee tests/samples/ubuntu_24.04/ip_addr_show_ens33.out

Guidelines
----------

- Samples go in a directory for the OS and version, such as ``ubuntu_18.04``, ``macos_10.12.6`` or ``windows_10``.
- Files are named after the command line with a ``.out`` extension, with spaces replaced by underscores, e.g. ``arp_-an.out``.
- Redact MACs, IPs, and hostnames you don't want to be public, but keep the output format intact. Locally administered MACs (``02:00:00:00:00:01``) and `documentation IP ranges <https://www.rfc-editor.org/info/rfc5737/>`__ (``192.0.2.0/24``) make good replacements.
- Windows samples must go in a directory whose name starts with ``windows``, so ``.gitattributes`` can preserve their Windows line endings (CRLF).
- Output taken from other projects goes in ``tests/samples/third_party/<project>/``, along with that project's license, and gets credited in the README.
- You should also capture what the command does for something that doesn't exist, along with the exit code (``echo $?`` when running it by hand). For example, ``ip addr show eth9`` prints ``Device "eth9" does not exist.`` and exits with code 1.


Write the method
================

Methods currently live in ``getmac/getmac.py``. Add the new class next to the methods with the same :attr:`~getmac.getmac.Method.method_type`. ``getmac/getmac.py`` already imports everything the example needs.

.. code-block:: python

   class IpAddrIface(Method):
       """
       Uses the ``ip addr show <iface>`` command to get the MAC address of an interface on Linux.

       Man page: `ip-address (8) <https://man7.org/linux/man-pages/man8/ip-address.8.html>`__
       """

       platforms = {"linux"}
       method_type = "iface"

       def test(self) -> bool:
           return utils.check_command("ip")

       def get(self, arg: str) -> Optional[str]:
           try:
               output = utils.popen("ip", f"addr show {arg}")
           except CalledProcessError as err:
               # 'Device "eth9" does not exist.' exits with code 1
               if err.returncode == 1:
                   return None
               raise  # Any other exit code means "ip" itself failed

           # The MAC is on the line after "<index>: <iface>: <FLAGS> ...".
           # "(?:@\w+)?" allows for container interface names like "eth0@if7".
           regex = r"^\d+: " + re.escape(arg) + r"(?:@\w+)?:.*\n\s+link/\S+ " + consts.MAC_RE_COLON
           return utils.search(regex, output, flags=re.MULTILINE)

Start the docstring with what the method uses and on which platform, and link to useful documentation (if relevant). The docstring appears in the :doc:`API reference <api>` automatically.

Class attributes
----------------

:attr:`~getmac.getmac.Method.platforms`
   The platforms the method works on, from :attr:`~getmac.getmac.Method.VALID_PLATFORM_NAMES`. getmac compares these with the detected platform, :attr:`~getmac.variables.Constants.PLATFORM` (the lowercase result of :func:`platform.system`), or with :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM` if it's set. Only list platforms where you've seen the method work.

   ``"other"`` is special. Methods that list it are used on platforms that have no methods of that type of their own.

:attr:`~getmac.getmac.Method.method_type`
   What the method looks up.

   - ``ip4``, ``ip6`` and ``ip`` (both) methods are given an IP address and return that host's MAC
   - ``iface`` methods are given an interface name (``"eth0"``) and return its MAC
   - ``default_iface`` methods are given an empty string and return the name of the default interface.

   :ref:`module-api-method-types` lists where each type is used.

:attr:`~getmac.getmac.Method.network_request`
   Set this to :obj:`True` if ``get()`` sends packets on the network, as :class:`~getmac.getmac.ArpingHost` and :class:`~getmac.getmac.CtypesHost` do.

The class name matters too. It's what :attr:`~getmac.variables.Settings.FORCE_METHOD` and ``--force-method`` match against (ignoring case), and it shows up in log messages, so renaming a method later can break things for users.

Follow the existing naming patterns, or use your own if none of the below apply:

- ``...Iface`` for interface lookups
- ``...Exe`` for Windows executables
- ``...File`` for reading files
- ``...Host`` for methods that send packets
- ``DefaultIface...`` for default interface methods

test()
------

:meth:`~getmac.getmac.Method.test` is a cheap check that the method could work on this system. getmac calls it the first time it needs a method of that type, so it shouldn't run the command or do anything slow.

Common checks are:

- :func:`utils.check_command("ip") <getmac.utils.check_command>`: the command is on the ``PATH`` and executable (a cached wrapper around :func:`shutil.which`).
- :func:`utils.check_path(path) <getmac.utils.check_path>`: a file or directory exists and is readable.
- Importing a standard library module inside a ``try`` block, as :class:`~getmac.getmac.FcntlIface` does.

If ``test()`` raises an exception, it's treated as if it returned :obj:`False`.

Some things can only be found out by running the command, such as which arguments the installed version accepts. Methods like :class:`~getmac.getmac.IpLinkIface` and :class:`~getmac.getmac.ArpVariousArgs` check this on their first ``get()`` call and cache the result.

get()
-----

:meth:`~getmac.getmac.Method.get` does the lookup. It returns the MAC address as a string, or :obj:`None` if it wasn't found. The MAC doesn't need to be pretty, since :func:`~getmac.getmac.get_mac_address` passes it through :func:`~getmac.utils.clean_mac`.

``default_iface`` methods don't use the argument, so they're declared as ``def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002``.

Return :obj:`None` when the interface or host isn't there.

Raise an exception or set ``self.unusable = True`` when the method itself doesn't work on this system (see :ref:`module-api-fallback`).

Helpers
-------

- :func:`utils.popen(command, args) <getmac.utils.popen>` runs a command and returns its output (stdout only) as a string. ``args`` is a single string. A non-zero exit code raises :class:`~subprocess.CalledProcessError`. Always call it as ``utils.popen(...)`` so tests can patch ``getmac.utils.popen``.
- :func:`utils.read_file(path) <getmac.utils.read_file>` returns a file's contents, or :obj:`None` if it can't be read.
- :func:`utils.search(regex, text) <getmac.utils.search>` returns the first capture group of the first match, or :obj:`None`. Use non-capturing groups (``(?:...)``) for everything except the MAC address.
- :attr:`consts.MAC_RE_COLON <getmac.variables.Constants.MAC_RE_COLON>`, :attr:`consts.MAC_RE_DASH <getmac.variables.Constants.MAC_RE_DASH>` (Windows style), and :attr:`consts.MAC_RE_SHORT <getmac.variables.Constants.MAC_RE_SHORT>` (allows single-digit octets, like ``58:6d:8f:7:c9:94``) match a MAC address in a single capture group.
- Log with ``gvars.log``, and wrap detailed debug messages in ``if settings.DEBUG:``.

When parsing output:

- Escape the argument with :func:`re.escape` before putting it in a regular expression.
- Make sure a partial argument can't match: ``eth`` must not match ``eth0``, and ``10.0.0.1`` must not match ``10.0.0.10``.
- Don't let a match run on into the next interface or host in the output, especially with :data:`re.DOTALL`.


Register it in METHODS
======================

Add the class to ``METHODS``, the list after the method classes in ``getmac/getmac.py``:

.. code-block:: python

   METHODS: list[type[Method]] = [
       ...
       IpLinkIface,
       IpAddrIface,
       NetstatIface,
       ...
   ]

The position in the list matters. getmac uses the first method of a type that passes ``test()`` on the current platform, in ``METHODS`` order, and keeps the others that pass as fallbacks (see :ref:`module-api-choosing`).

Put faster and more reliable methods first: reading a file or calling a library before running a command (which spawns a process and is slow), and specific commands before generic catch-alls.

Write tests
===========

Method tests go in ``tests/test_methods.py``. They must not run real commands or depend on what's installed on the system. Instead, load the sample with the ``get_sample`` fixture and patch the appropriate functions with ``mocker.patch``.

Most methods have two tests: one parametrized over the samples, and one for edge cases. ``tests/test_methods.py`` already imports everything these need. Additionally, the sample tests are usually wrapped in ``benchmark(...)`` to run performance benchmarks (when enabled, e.g. ``pdm run benchmark``).

.. code-block:: python

   @pytest.mark.parametrize(
       ("mac", "iface", "sample_file"),
       [
           ("02:00:00:00:00:01", "ens33", "ubuntu_24.04/ip_addr_show_ens33.out"),
           ("08:00:27:e8:81:6f", "eth0", "ubuntu_12.04/ip_a.out"),
           ("00:00:00:00:00:00", "lo", "ubuntu_12.04/ip_a.out"),
       ],
   )
   def test_ipaddriface_samples(benchmark, mocker, get_sample, mac, iface, sample_file):
       content = get_sample(sample_file)
       mocker.patch("getmac.utils.popen", return_value=content)
       assert mac == benchmark(getmac.IpAddrIface().get, arg=iface)

       # Partial and unknown interface names must not match
       for wrong_iface in ("eth", "th0", "ens3", "ens333", "lo0"):
           assert getmac.IpAddrIface().get(wrong_iface) is None


   def test_ipaddriface_edge_cases(mocker):
       mocker.patch("getmac.utils.check_command", return_value=False)
       assert getmac.IpAddrIface().test() is False
       utils.check_command.assert_called_once_with("ip")

       mocker.patch("getmac.utils.popen", return_value="")
       assert getmac.IpAddrIface().get("eth0") is None
       utils.popen.assert_called_once_with("ip", "addr show eth0")

       # Exit code 1 means "not found", any other code is raised
       cpe = CalledProcessError(cmd="ip", returncode=1)
       mocker.patch("getmac.utils.popen", side_effect=cpe)
       assert getmac.IpAddrIface().get("eth9") is None

       cpe = CalledProcessError(cmd="ip", returncode=255)
       mocker.patch("getmac.utils.popen", side_effect=cpe)
       with pytest.raises(CalledProcessError):
           getmac.IpAddrIface().get("eth0")

Things to cover:

- The expected value is what ``get()`` returns, before :func:`~getmac.utils.clean_mac`.
- Partial and wrong names or addresses return :obj:`None`.
- ``test()`` checks the right command or path (``assert_called_once_with``).
- Empty output, exit codes, and anything that sets ``unusable``.

Tests run in parallel and in random order, so only change global state (settings, caches, platform flags in ``consts``) with ``mocker``, which undoes the change after the test, e.g. ``mocker.patch.object(consts, "DARWIN", True)``.

To run just the new tests:

.. code-block:: shell

   pdm run test tests/test_methods.py -k ipaddriface


Try it on a real system
=======================

.. code-block:: shell

   pdm run getmac -dddd -i ens33 --force-method IpAddrIface

``-dddd`` logs the command and its raw output.

``-dd`` logs which methods were considered, which passed ``test()``, and which one was chosen:

.. code-block:: shell

   pdm run getmac -dd -i ens33

``--override-platform`` makes getmac choose methods as if it were running on a different platform.


Finish up
=========

- Add the command, file, or library to "Commands and techniques by platform" in ``README.md``, and update "Platforms currently supported" if needed.
- Add an entry to ``CHANGELOG.md`` under "Added" for the upcoming release, in plain language.
- Follow the checklist in :doc:`contributing` and open a pull request!
