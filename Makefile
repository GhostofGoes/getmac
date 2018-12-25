.PHONY: install clean clean-build clean-all check test build upload

install: clean clean-build
	@pip install -e .

clean:
	@find . -name '*.pyc' -delete
	@find . -name '*.pyo' -delete
	@find . -name '__pycache__' -delete
	@find . -name '*~' -delete

clean-build:
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg

clean-all: clean clean-build
	@rm -rf .tox/
	@rm -rf .pytest_cache/
	@rm -rf .coverage.py*
	@rm -rf .mypy_cache/
	@rm -rf *.egg-info

check: clean
	@tox -e check

test: check
	@tox

build: clean clean-build
	@python setup.py sdist bdist_wheel

upload: build
	pip install 'twine>=1.11.0'
	twine upload dist/*

gen-stubs: clean
	stubgen --recursive -o '.\typestubs' getmac
	cat ./typestubs/getmac/getmac.pyi
