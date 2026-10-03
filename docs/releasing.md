
## Requirements
**NOTE**: Linux is required to build the `.deb` package.

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y build-essential fakeroot debhelper dh-python python3-all python3.11 python3.11-venv

python3.11 -m venv ~/py311venv
source ~/py311venv/bin/activate

pip install setuptools twine wheel
pip install -U stdeb
```

## Cutting a release
1. Increment version number in `getmac/getmac.py`
2. Update CHANGELOG header from UNRELEASED to the version and add the date
3. Run static analysis checks (`tox -e check`)
4. Run the test suite on the main supported platforms (`tox`)
    a) Windows
    b) Ubuntu
    c) CentOS
    d) OSX
5. Ensure a pip install from source works on the main platforms:
```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```
6. Clean the environment: `bash ./scripts/clean.sh`
7. Build the sdist and wheel (`.whl`)
```bash
python setup.py sdist bdist_wheel --universal
```
8. Upload the sdist and wheel (`.whl`)
```bash
twine upload dist/*
```
9. Build the Debian package. `nocheck` skips the Debian test step. Must be run in a weird way. This project is getting rickity, need 1.0 release already.
```bash
deactivate
rm -rf deb_dist && DEB_BUILD_OPTIONS=nocheck /home/cgoes/py311env/bin/python setup.py --command-packages=stdeb.command bdist_deb
```
10. Create a tagged release on GitHub including:
    a) The relevant section of the CHANGELOG in the body
    b) The source and binary wheels
    c) The `.deb` package (which will be in `./deb_dist`)
11. Edit the package name in `setup.py` to `get-mac`, and re-run steps 7 and 8 (build and upload), since people apparently don't check their dependencies and ignore runtime warnings.
12. Announce the release in the normal places
