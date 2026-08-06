#!/bin/sh
# Basic Provisioning for Ubuntu

set -e

sudo apt-get update -y
sudo apt-get install -y \
    git make dos2unix nano \
    python python-pip python-setuptools python-virtualenv python-dev \
    python3 python3-pip python3-setuptools python3-virtualenv python3-dev

# Pull down the codebase
cd "$HOME" || exit
git clone https://github.com/GhostofGoes/getmac.git

# Create Python virtual environments
mkdir -p "$HOME/.virtualenvs/"
python3 -m virtualenv --python=python3 "$HOME/.virtualenvs/getmac"
