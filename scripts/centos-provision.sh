#!/bin/sh
# Basic Provisioning for CentOS7
# -y: 'yes' to all prompts
# -t: continues through errors (so our whole system setup isn't halted by some repo error)
# -q: quiet

sudo yum -y -t -q update
sudo yum -y -t -q install epel-release
sudo yum -y -t -q install yum-utils git make dos2unix nano python-pip python-virtualenv

# https://stackoverflow.com/a/23317640/2214380
sudo yum -y -t -q install python34 python34-setuptools
sudo easy_install-3.4 pip
sudo pip3 install virtualenv

# Pull down the codebase
git clone https://github.com/GhostofGoes/get-mac.git

# Create Python virtual environments
mkdir -p "$HOME/.virtualenvs/"
python3 -m virtualenv --python=python3 "$HOME/.virtualenvs/getmac34"
python -m virtualenv --python=python2 "$HOME/.virtualenvs/getmac27"
