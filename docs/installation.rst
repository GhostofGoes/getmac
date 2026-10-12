============
Installation
============

Stable release from PyPI
========================

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m pip install getmac

.. tab:: Windows

   .. code-block:: powershell

      py -m pip install getmac


Debian-based Linux distributions
================================

Some Linux distributions have a getmac package in ``apt``. The packaging status below shows which distributions have it.

.. code-block:: shell

   sudo apt install getmac


OS Packaging Status
===================

.. image:: https://repology.org/badge/vertical-allrepos/getmac.svg
   :alt: OS Packaging status
   :target: https://repology.org/project/getmac/versions


Latest development version
==========================

.. warning::
   The main branch contains changes that are not released yet. Most users should install the stable release instead.

These commands install the latest version from the main branch on GitHub.

.. tab:: Linux/macOS

   .. code-block:: shell

      python3 -m pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz

.. tab:: Windows

   .. code-block:: powershell

      py -m pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz



Older Python versions
=====================

getmac 1.0.0 and later need Python 3.9 or newer. For an older Python, install an older version of getmac that supports it:

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

The wheels are on the `GitHub releases page <https://github.com/GhostofGoes/getmac/releases>`__ and on PyPI. To install them from PyPI, you may need a current version of ``pip`` and some extra arguments.

.. note::
   These older versions do not have many of the performance improvements, platform support, and bug fixes of later releases.

To move from 0.9.x to 1.0.0, see :doc:`upgrading`.
