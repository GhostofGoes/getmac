# Building Debian packages

To create Debian .deb packages simply use stdeb module

    # Create isolated environment to not spam OS
    python3 -m virtualenv -p /usr/bin/python3 venv
    source venv/bin/activate
    pip install stdeb

    # Now build Debian packages
    python3 setup.py --command-packages=stdeb.command bdist_deb

Done your Debian packages is located under deb_dist

    ls -l deb_dist/python3-getmac_0.6.0-1_all.deb
    -rw-r--r-- 1 kofrezo kofrezo 20402 Okt 19 20:35 deb_dist/python3-getmac_0.6.0-1_all.deb

