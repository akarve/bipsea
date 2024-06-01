.PHONY: all build check clean install install-go lint push test test-network git-unsaved

build: clean check
	python -m build

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache dist

check:
	black . --check
	isort . --check

# developer install only
install:
	pip install -r requirements.txt -r test-requirements.txt
	pip install -e .

install-go:
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest
	go install github.com/mrtazz/checkmake/cmd/checkmake@latest

lint:
	isort .
	black .
	actionlint
	checkmake Makefile

publish: build
	python3 -m twine upload dist/*

push: lint check test git-branch git-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

test:
	pytest tests -m "not network" -sx

test-network:
	pytest tests

git-branch:
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" = "main" ]; then \
		echo "Cowardly refusing push, not on branch."; \
		exit 1; \
	fi

git-unsaved:
	@if ! git diff --quiet; then \
		echo "There are unsaved changes in the git repository."; \
		exit 1; \
	fi
