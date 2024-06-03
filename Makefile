.PHONY: all build check clean git-branch git-unsaved install install-dev install-go
.PHONY: lint publish push readme-cmds test test-network uninstall-dev

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

test: readme-cmds
	pytest -vsx

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


readme-cmds:
	bipsea seed -t words -n 12 --pretty
	bipsea seed -f words -u "airport letter idea forget broccoli prefer panda food delay struggle ridge salute above want dinner"
	bipsea seed -f words -u "123456123456123456" --not-strict
	bipsea seed -f words -u "$$(cat README.md)" --not-strict
	bipsea seed | bipsea entropy
	bipsea seed -f words -u "load kitchen smooth mass blood happy kidney orbit used process lady sudden" | bipsea entropy -n 12
	bipsea seed -f words -u "load kitchen smooth mass blood happy kidney orbit used process lady sudden" | bipsea entropy -n 12 -i 1
	bipsea seed -f words -u "satoshi nakamoto" --not-strict | bipsea entropy -a base85 -n 10
	bipsea seed -f words -u "satoshi nakamoto" --not-strict | bipsea entropy -a base85 -n 10 -i 1
	bipsea entropy -a base85 -n 10 --input "$$(bipsea seed)"
	bipsea seed -t xprv | bipsea entropy -a drng -n 10
