===================
Adding a new method
===================

getmac uses *methods* to find MAC addresses. A method is a subclass of :class:`~getmac.getmac.Method` that uses one technique to get a MAC. Examples are to run a command and to read a file. To support a new command, file, or platform, add a new method.

To use a custom method in your own code without a change to getmac, see :doc:`module_api`. To set up a development environment, and for the rules for pull requests, see :doc:`contributing`.

The examples on this page use an example method, ``IpAddrIface``. It is not part of getmac. It gets the MAC address of an interface on Linux from the output of ``ip addr show <iface>``.


Collect sample output
=====================

The method tests use real command output from ``tests/samples/``. Thus, first record the output on the platform of the method. For the example method, the command is ``ip addr`` on Linux.

``scripts/collect_samples.py`` runs the commands that getmac uses on the current platform. It saves the output of each command to a file in ``tests/samples/<platform>_<version>/``, for example ``tests/samples/ubuntu_24.04/``. It writes the exit codes and error messages to ``collect_samples.log`` in the same directory. The script needs only Python. Thus, you can copy it to a machine that does not have getmac. A copy outside the repository saves to ``./samples/<platform>_<version>/``, or to the directory that you give with ``--output-root``.

.. code-block:: shell

   python scripts/collect_samples.py --dry-run  # Show the samples, but do not collect them
   python scripts/collect_samples.py  # Collect the samples

You can also run the command manually, and save the output with ``tee``:

.. code-block:: shell

   mkdir -p tests/samples/ubuntu_24.04
   ip addr show ens33 | tee tests/samples/ubuntu_24.04/ip_addr_show_ens33.out

Guidelines
----------

- Put the samples in a directory for the OS and version, such as ``ubuntu_18.04``, ``macos_10.12.6`` or ``windows_10``.
- Give each file the name of the command line, with underscores instead of spaces, and a ``.out`` extension. For example: ``arp_-an.out``.
- Replace the MACs, IPs, and hostnames that you do not want to make public. Do not change the output format. Good replacements are locally administered MACs (``02:00:00:00:00:01``) and `documentation IP ranges <https://www.rfc-editor.org/info/rfc5737/>`__ (``192.0.2.0/24``).
- Put Windows samples in a directory whose name starts with ``windows``. Then ``.gitattributes`` keeps their Windows line endings (CRLF).
- Put output from other projects in ``tests/samples/third_party/<project>/``, with the license of that project. Credit the project in the README.
- Also record the output of the command for an item that does not exist, and the exit code. To see the exit code when you run the command manually, use ``echo $?``. For example, ``ip addr show eth9`` prints ``Device "eth9" does not exist.`` and exits with code 1.


Write the method
================

The methods are in ``getmac/getmac.py``. Add the new class near the methods with the same :attr:`~getmac.getmac.Method.method_type`. ``getmac/getmac.py`` already imports all the items that the example needs.

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

Start the docstring with the command or file that the method uses, and the platform. If useful documentation exists, add a link to it. The :doc:`API reference <api>` shows the docstring automatically.

Class attributes
----------------

:attr:`~getmac.getmac.Method.platforms`
   The platforms that the method works on, from :attr:`~getmac.getmac.Method.VALID_PLATFORM_NAMES`. getmac compares these values with the detected platform, :attr:`~getmac.variables.Constants.PLATFORM`. This is the lowercase result of :func:`platform.system`. If :attr:`~getmac.variables.Settings.OVERRIDE_PLATFORM` is set, getmac uses that value instead. List only the platforms where you saw the method work.

   ``"other"`` is a special value. getmac uses the methods that list it on platforms that have no methods of that type.

:attr:`~getmac.getmac.Method.method_type`
   The type of lookup that the method does.

   - ``ip4``, ``ip6`` and ``ip`` (both) methods are given an IP address and return that host's MAC
   - ``iface`` methods are given an interface name (``"eth0"``) and return its MAC
   - ``default_iface`` methods are given an empty string and return the name of the default interface.

   :ref:`module-api-method-types` lists where each type is used.

:attr:`~getmac.getmac.Method.network_request`
   Set this to :obj:`True` if ``get()`` sends packets on the network. :class:`~getmac.getmac.ArpingHost` and :class:`~getmac.getmac.CtypesHost` are examples.

The class name is also important. :attr:`~getmac.variables.Settings.FORCE_METHOD` and ``--force-method`` use it to find the method, and ignore case. The name also shows in log messages. Thus, a new name for a method in a later release can break the configuration of users.

Use the naming patterns below. If none of them apply, use your own name:

- ``...Iface`` for interface lookups
- ``...Exe`` for Windows executables
- ``...File`` for reading files
- ``...Host`` for methods that send packets
- ``DefaultIface...`` for default interface methods

test()
------

:meth:`~getmac.getmac.Method.test` is a fast check that the method can work on this system. getmac calls it the first time that it needs a method of that type. Thus, it must not run the command or do other slow operations.

Usual checks are:

- :func:`utils.check_command("ip") <getmac.utils.check_command>`: the command is on the ``PATH`` and you can run it. This function keeps the results of :func:`shutil.which` in a cache.
- :func:`utils.check_path(path) <getmac.utils.check_path>`: a file or directory exists and is readable.
- An import of a standard library module in a ``try`` block. :class:`~getmac.getmac.FcntlIface` does this.

If ``test()`` raises an exception, getmac uses the result :obj:`False`.

Some information is available only when the command runs. An example is the arguments that the installed version accepts. Methods such as :class:`~getmac.getmac.IpLinkIface` and :class:`~getmac.getmac.ArpVariousArgs` check this at their first ``get()`` call, and keep the result in a cache.

get()
-----

:meth:`~getmac.getmac.Method.get` does the lookup. It returns the MAC address as a string, or :obj:`None` if it does not find the MAC. The format of the MAC is not important, because :func:`~getmac.getmac.get_mac_address` cleans it with :func:`~getmac.utils.clean_mac`.

``default_iface`` methods do not use the argument. Thus, declare them as ``def get(self, arg: str = "") -> Optional[str]:  # noqa: ARG002``.

Return :obj:`None` when the interface or host does not exist.

If the method does not work on this system, raise an exception or set ``self.unusable = True``. See :ref:`module-api-fallback`.

Helpers
-------

- :func:`utils.popen(command, args) <getmac.utils.popen>` runs a command and returns its output (stdout only) as a string. ``args`` is one string. An exit code that is not zero raises :class:`~subprocess.CalledProcessError`. Always call it as ``utils.popen(...)``, so that tests can patch ``getmac.utils.popen``.
- :func:`utils.read_file(path) <getmac.utils.read_file>` returns the contents of a file. If it cannot read the file, it returns :obj:`None`.
- :func:`utils.search(regex, text) <getmac.utils.search>` returns the first capture group of the first match, or :obj:`None`. Use non-capturing groups (``(?:...)``) for everything except the MAC address.
- :attr:`consts.MAC_RE_COLON <getmac.variables.Constants.MAC_RE_COLON>`, :attr:`consts.MAC_RE_DASH <getmac.variables.Constants.MAC_RE_DASH>` (Windows style), and :attr:`consts.MAC_RE_SHORT <getmac.variables.Constants.MAC_RE_SHORT>` (allows single-digit octets, like ``58:6d:8f:7:c9:94``) match a MAC address in a single capture group.
- Use ``gvars.log`` for log messages. Put detailed debug messages in an ``if settings.DEBUG:`` block.

When you parse output:

- Use :func:`re.escape` on the argument before you put it in a regular expression.
- Make sure that a partial argument does not match. ``eth`` must not match ``eth0``, and ``10.0.0.1`` must not match ``10.0.0.10``.
- Make sure that a match does not continue into the next interface or host in the output. This is important with :data:`re.DOTALL`.


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

The position in the list is important. getmac uses the first method of a type that passes ``test()`` on the current platform, in the order of ``METHODS``. It keeps the other methods that pass as fallbacks. See :ref:`module-api-choosing`.

Put faster and more reliable methods first:

- Put methods that read a file or call a library before methods that run a command. A command starts a new process, which is slow.
- Put methods for specific commands before general methods.

Write tests
===========

Put the method tests in ``tests/test_methods.py``. The tests must not run real commands. They must not depend on the software that is installed on the system. Load the sample with the ``get_sample`` fixture instead, and patch the necessary functions with ``mocker.patch``.

Most methods have two tests. One test is parametrized over the samples, and one test is for edge cases. ``tests/test_methods.py`` already imports all the items that these tests need. The sample tests usually call the method through ``benchmark(...)``. This runs performance benchmarks when you enable them, for example with ``pdm run benchmark``.

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

The tests must cover these items:

- The expected value is the value that ``get()`` returns, before :func:`~getmac.utils.clean_mac`.
- Partial and wrong names or addresses return :obj:`None`.
- ``test()`` checks the right command or path (``assert_called_once_with``).
- Empty output, exit codes, and all conditions that set ``unusable``.

The tests run in parallel and in a random order. Thus, change global state only with ``mocker``, which undoes the change after the test. Global state includes the settings, the caches, and the platform flags in ``consts``. For example: ``mocker.patch.object(consts, "DARWIN", True)``.

To run only the new tests:

.. code-block:: shell

   pdm run test tests/test_methods.py -k ipaddriface


Try it on a real system
=======================

.. code-block:: shell

   pdm run getmac -dddd -i ens33 --force-method IpAddrIface

``-dddd`` logs the command and its raw output.

``-dd`` logs the methods that getmac examined, the methods that passed ``test()``, and the method that getmac selected:

.. code-block:: shell

   pdm run getmac -dd -i ens33

``--override-platform`` makes getmac select methods for a different platform.


Finish up
=========

- Add the command, file, or library to :doc:`platforms` and to "Commands and techniques by platform" in ``README.md``. If necessary, also update the supported platforms in the same files.
- Add an entry to ``CHANGELOG.md``, under "Added" for the next release. Use plain language.
- Do the checklist in :doc:`contributing`, and open a pull request.
