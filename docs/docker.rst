======
Docker
======

A Docker image of the ``getmac`` command is available from the `GitHub Container Registry <https://github.com/GhostofGoes/getmac/pkgs/container/getmac>`__. The image is for ``linux/amd64`` and ``linux/arm64``.

The container runs ``getmac`` as an unprivileged user (``nobody``). The container gives all arguments to ``getmac``.

.. code-block:: shell

   docker run --rm ghcr.io/ghostofgoes/getmac --help
   docker run --rm ghcr.io/ghostofgoes/getmac --version
   docker run --rm ghcr.io/ghostofgoes/getmac -n localhost

Tags
====

- ``latest``: the newest stable release.
- ``<version>``: each release also has tags for its version, for example ``1.0.0``, ``1.0`` and ``1``. Pre-releases have only the tag for their version.
- ``edge``: built from the ``main`` branch.

Networks
========

By default, the container is on the bridge network of Docker. Thus, the container sees its own interfaces and its own ARP table, not the interfaces and ARP table of the host.

- On Linux, to look up the interfaces of the host, use ``--network host``.
- In bridge mode, to read the ARP table of the host, add ``-v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp``.
- With Docker Desktop on macOS and Windows, the container sees only the network of the Docker VM, not the network of your computer.
- IPv6 lookups (``-6``) need a Docker network with IPv6 enabled.

.. code-block:: shell

   docker run --rm --network host ghcr.io/ghostofgoes/getmac
   docker run --rm -v /proc/1/net/arp:/host/arp:ro -e ARP_PATH=/host/arp ghcr.io/ghostofgoes/getmac -4 192.168.0.1

Build the image
===============

To build the image yourself, see the Docker section of :doc:`contributing`.
