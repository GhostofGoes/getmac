# Building Debian apt package

```bash
pip install stdeb
python setup.py --command-packages=stdeb.command bdist_deb
ls -lhAt ./deb_dist
```

# Building Yum package
TBD
