#!/usr/bin/env bash

find . -name '*.pyc' -delete
find . -name '*.pyo' -delete
find . -name '__pycache__' -delete
find . -name '*~' -delete

rm -f getmac-*.tar.gz
rm -rf build/
rm -rf dist/
rm -rf deb_dist/
rm -rf *.egg
rm -rf *.egg-info

rm -rf .tox/
rm -rf .pytest_cache/
rm -rf .mypy_cache/
rm -rf htmlcov
rm -f .coverage.coverage
