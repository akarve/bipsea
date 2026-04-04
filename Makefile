.PHONY: all build check check-version-sync clean download-lists install install-ci install-dist install-go lint publish push test test-all test-dist test-integration

all:: install build

test::
	poetry run pytest -n auto

test-all::
	poetry run pytest -n auto -m ""

test-dist:: clean build install-dist test-integration
	# after run `make install-ci` to restore dev deps

test-integration::
	poetry run pytest "tests/test_cli.py::TestIntegration" -m "" -n auto

push:: git-off-main git-no-unsaved lint test-all
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

publish:: download-lists git-no-unsaved git-on-main check-version-sync test-dist install-ci test
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

check:: check-version-sync
	poetry run black . --check
	poetry run isort . --check
	poetry run flake8 . --ignore=E501,W503,E704
	bash -n scripts/*.sh
	bash -n tests/*.sh

check-version-sync::
	@poetry run python -c "import pathlib,re,sys; p=pathlib.Path('pyproject.toml').read_text(); u=pathlib.Path('src/bipsea/util.py').read_text(); pv=re.search(r'(?m)^version\\s*=\\s*\"([^\"]+)\"', p).group(1); uv=re.search(r'(?m)^__version__\\s*=\\s*\"([^\"]+)\"', u).group(1); sys.exit(0) if pv==uv else sys.exit(f'Version mismatch: pyproject.toml={pv} util.py={uv}')"

lint::
	isort .
	black .
	actionlint
	flake8 . --ignore=E501,W503,E704
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
	@if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "There are unsaved changes in the git repository."; \
		exit 1; \
	fi
