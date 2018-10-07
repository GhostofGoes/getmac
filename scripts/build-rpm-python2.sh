sudo dnf install gcc rpm-build rpm-devel rpmlint make python bash coreutils diffutils patch rpmdevtools
rpmdev-setuptree
mkdir getmac-0.5
cp -rt getmac-0.5 getmac setup.py README.md LICENSE
tar czf get-mac-0.5.0.tar.gz getmac-0.5
mv get-mac-0.5.0.tar.gz ~/rpmbuild/SOURCES/
cp python2-getmac.spec ~/rpmbuild/SPECS/
cd ~/rpmbuild/SPECS/
rpmbuild -bs python2-getmac.spec
rpmbuild -bb python2-getmac.spec
rm -rf getmac-0.5