.PHONY: install clean clean-build test build

install: clean
	@pip install -e .

clean:
	@find . -name '*.pyc' -delete
	@find . -name '*.pyo' -delete
	@find . -name '__pycache__' -delete
	@find . -name '*~' -delete

clean-build: clean
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info

test:
	@python -m unittest discover -s ./test

build: clean-build
	@python setup.py sdist bdist_wheel
