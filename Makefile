.PHONY: all build check clean git-branch git-unsaved install install-dev install-go
.PHONY: lint publish push test test-network uninstall-dev

build: clean check test
	python -m build

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache dist

check:
	black . --check
	isort . --check

install:
	pip install -r requirements.txt -r test-requirements.txt

install-dev: uninstall-dev
	pip install -e .

install-go:
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest
	go install github.com/mrtazz/checkmake/cmd/checkmake@latest

uninstall-dev:
	pip uninstall -y bipsea

lint:
	isort .
	black .
	actionlint
	checkmake Makefile

publish: build git-unsaved git-main
	git pull origin main
	python3 -m twine upload dist/*

push: lint check test git-branch git-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

test: install-dev
	pytest tests -m "not network" -sx

test-network:
	pytest tests

git-branch:
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" = "main" ]; then \
		echo "Cowardly refusing push from main."; \
		exit 1; \
	fi

git-main:
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" != "main" ]; then \
		echo "Must be on main branch."; \
		exit 1; \
	fi

git-unsaved:
	@if ! git diff --quiet; then \
		echo "There are unsaved changes in the git repository."; \
		exit 1; \
	fi
