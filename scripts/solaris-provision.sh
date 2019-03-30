#!/usr/bin/env bash

sudo pkgadd -d http://get.opencsw.org/now
sudo /opt/csw/bin/pkgutil -U
sudo /opt/csw/bin/pkgutil -y -i python27
sudo /opt/csw/bin/pkgutil -y -i py_pip
