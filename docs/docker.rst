======
Docker
======

A Docker image of the ``getmac`` command is published to the `GitHub Container Registry <https://github.com/GhostofGoes/getmac/pkgs/container/getmac>`__ for ``linux/amd64`` and ``linux/arm64``. The container runs ``getmac`` as an unprivileged user (``nobody``), and any arguments are passed to it.

.. code-block:: shell

   docker run --rm ghcr.io/ghostofgoes/getmac --help
   docker run --rm ghcr.io/ghostofgoes/getmac --version
   docker run --rm ghcr.io/ghostofgoes/getmac -n localhost

Tags
====

- ``latest``: the newest stable release.
- ``1.0.0``, ``1.0``, ``1``: releases are also tagged with their version. Pre-releases are only tagged with their version.
- ``edge``: built from the ``main`` branch.

Networking
==========

By default the container is on Docker's bridge network, so it sees its own interfaces and :term:`ARP table`, not the host's.

- On Linux, use ``--network host`` to look up the host's interfaces.
- In bridge mode, add ``-v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp`` to read the host's ARP table. ``ARP_PATH`` tells getmac where to find the ARP table (``/proc/net/arp`` by default). See :ref:`usage-environment`.
- With Docker Desktop on macOS and Windows, the container only sees the Docker VM's network, not your computer's.
- IPv6 lookups (``-6``) need a Docker network with IPv6 enabled.

.. code-block:: shell

   docker run --rm --network host ghcr.io/ghostofgoes/getmac
   docker run --rm -v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp ghcr.io/ghostofgoes/getmac -4 192.168.0.1

Verifying the image
===================

Published images have a signed build provenance attestation from GitHub, which can be checked with the `GitHub CLI <https://cli.github.com/>`__. See :doc:`security` for the details.

.. code-block:: shell

   gh attestation verify oci://ghcr.io/ghostofgoes/getmac:1.0.0 --repo GhostofGoes/getmac

Building the image
==================

To build the image yourself, see the Docker section of :doc:`contributing`.
