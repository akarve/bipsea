.PHONY: all clean install test

all:: install build

test::
	poetry run pytest -n auto

test-all::
	poetry run pytest -n auto -m ""

test-dist:: clean build install-dist test-integration

test-integration::
	poetry run pytest "tests/test_cli.py::TestIntegration" -m "" -n auto

push:: lint test-all git-off-main git-no-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

build: install-ci
	poetry build

download-lists::
	bash scripts/download-lists.sh

clean::
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache
	pip uninstall -y bipsea

publish:: download-lists git-no-unsaved git-on-main test-dist install-ci test
	poetry publish

install:: install-ci install-go

install-ci::
	poetry install --with dev

install-go::
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest
	go install github.com/mrtazz/checkmake/cmd/checkmake@latest

install-dist::
	poetry install --without dev

check::
	poetry run black . --check
	poetry run isort . --check
	poetry run flake8 . --ignore=E501,W503
	bash -n scripts/*.sh

lint::
	isort .
	black .
	actionlint
	flake8 . --ignore=E501,W503
	checkmake Makefile

git-off-main::
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" = "main" ]; then \
		echo "Cowardly refusing push from main."; \
		exit 1; \
	fi

git-on-main::
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" != "main" ]; then \
		echo "Must be on main branch."; \
		exit 1; \
	fi

git-no-unsaved::
	@if ! git diff --quiet; then \
		echo "There are unsaved changes in the git repository."; \
		exit 1; \
	fi
