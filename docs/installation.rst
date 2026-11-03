============
Installation
============

getmac supports Python 3.9 and newer, on :term:`CPython` and :term:`PyPy`, and has no dependencies.

Stable release from PyPI
========================

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m pip install getmac

.. tab:: Windows

   .. code-block:: powershell

      py -m pip install getmac

This also installs the ``getmac`` command (see :doc:`cli`).


Pre-releases from PyPI
======================

Alpha, beta, and release candidate versions of getmac are published to :term:`PyPI` before a stable release. ``pip`` skips them unless you ask for them with the ``--pre`` flag.

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m pip install --pre getmac

.. tab:: Windows

   .. code-block:: powershell

      py -m pip install --pre getmac

You can also pin a specific pre-release, for example ``python3 -m pip install getmac==1.0.0rc1``. Pre-releases may have bugs and their behavior may change before the stable release, so please `report any issues <https://github.com/GhostofGoes/getmac/issues>`__ you run into.


Debian-based Linux distributions
================================

``apt`` may have it available, depending on the Linux distribution (see the packaging status below). The packaged version may be older than the one on PyPI.

.. code-block:: shell

   sudo apt install getmac


OS Packaging Status
===================

To see which operating systems package getmac, and which version each one has, check `getmac's packaging status on Repology <https://repology.org/project/getmac/versions>`__.


Docker
======

There's also a Docker image of the ``getmac`` command. See :doc:`docker`.


Latest development version
==========================

.. warning::
   Installing directly from ``main`` includes pre-release changes and is not recommended for most users.

This will install the latest version from the ``main`` branch on GitHub.

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz

.. tab:: Windows

   .. code-block:: powershell

      py -m pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz


Legacy Python versions
======================

If you are running an old Python (3.8 and older) or interpreter, then you can install an older version of getmac that supported that version. The :term:`wheels <wheel>` are available in the `GitHub releases <https://github.com/GhostofGoes/getmac/releases>`__, or from PyPI with a current version of ``pip`` and some special arguments.

.. list-table::
   :header-rows: 1

   * - Python version
     - Package to install
   * - 2.5
     - ``get-mac==0.5.0``
   * - 2.6
     - ``getmac==0.6.0``
   * - 2.7
     - ``getmac<1.0.0``
   * - 3.2, 3.3
     - ``get-mac==0.3.0``
   * - 3.4 to 3.8
     - ``getmac<1.0.0``

.. note::
   These versions do not have many of the performance improvements, platform support, and bug fixes that came with later releases. They generally work, just not as well.

If you're moving from 0.9.x to 1.0.0, see :doc:`upgrading`.
