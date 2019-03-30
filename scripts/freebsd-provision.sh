#!/usr/bin/env bash

sudo pkg update
sudo pkg install -y py36-pip py27-pip py27-virtualenv-16.0.0

mkdir -p "$HOME/.virtualenvs/"
python3.6 -m venv "$HOME/.virtualenvs/getmac36"
python2.7 -m virtualenv "$HOME/.virtualenvs/getmac27"
