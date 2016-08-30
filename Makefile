SHELL=/bin/bash -e

wheel: lint clean
	./setup.py bdist_wheel

test_deps:
	pip install coverage flake8

lint: test_deps
	python setup.py flake8

test: test_deps lint
	coverage run setup.py test

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install: clean
	python ./setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

.PHONY: wheel lint test test_deps docs install clean

include common.mk
