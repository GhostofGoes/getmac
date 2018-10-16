#!/usr/bin/env bash

sudo dnf install gcc rpm-build rpm-devel rpmlint make python bash coreutils diffutils patch rpmdevtools
rpmdev-setuptree
mkdir getmac-$1
mkdir getmac-$1/docs
mkdir getmac-$1/docs/man
cp -rt getmac-$1 getmac setup.py README.md LICENSE
cp docs/man/getmac.1 getmac-$1/docs/man
tar czf getmac-$1.tar.gz getmac-$1
mv getmac-$1.tar.gz ~/rpmbuild/SOURCES/
cp python3-getmac.spec ~/rpmbuild/SPECS/
rm -rf getmac-$1
cd ~/rpmbuild/SPECS/
rpmbuild -bs python3-getmac.spec
rpmbuild -bb python3-getmac.spec
