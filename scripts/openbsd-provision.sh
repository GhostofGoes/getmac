#!/usr/bin/env bash

sudo pkg_add python-2.7.15p0 python-3.6.6p1 \
     py-pip-9.0.3 py3-pip-9.0.3 \
     py-virtualenv-16.0.0

# Workaround for $HOME not being mounted as wxallowed
# http://openbsd-archive.7691.n7.nabble.com/Best-Practices-python-virtualenv-td342219.html
sudo mkdir -p "/usr/local/.virtualenvs/"
sudo chown vagrant: /usr/local/.virtualenvs/
python3 -m venv "/usr/local/.virtualenvs/getmac36"
python2 -m virtualenv "/usr/local/.virtualenvs/getmac27"

sudo updatedb
