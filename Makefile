.PHONY: install clean clean-build test build upload

install: clean
	@pip install -e .

clean:
	@find . -name '*.pyc' -delete
	@find . -name '*.pyo' -delete
	@find . -name '__pycache__' -delete
	@find . -name '*~' -delete

clean-build: clean
	@rm -rf build dist *.egg *.egg-info

test:
	@python -m unittest discover -s ./tests
	@tox

build: clean-build
	@python setup.py sdist bdist_wheel

upload: build
	pip install 'twine>=1.11.0'
	twine upload dist/*
