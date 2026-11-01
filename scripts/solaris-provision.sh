#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2017-2026 Christopher Goes
# SPDX-License-Identifier: MIT

sudo pkgadd -d http://get.opencsw.org/now
sudo /opt/csw/bin/pkgutil -U
sudo /opt/csw/bin/pkgutil -y -i python27
sudo /opt/csw/bin/pkgutil -y -i py_pip
