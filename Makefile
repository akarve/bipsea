.PHONY: all build check clean git-no-unsaved git-on-main got-off-main install install-dev
.PHONY: install-go lint publish push readme-cmds test test-network uninstall-dev

build: clean download-wordlists check test
	python3 -m build

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache dist

check:
	black . --check
	isort . --check

install:
	pip install -r requirements.txt -r tst-requirements.txt

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

publish: build git-no-unsaved git-on-main
	git pull origin main
	python3 -m twine upload dist/*

push: lint check test git-off-main git-no-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

test: readme-cmds
	pytest -vsx

git-off-main:
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" = "main" ]; then \
		echo "Cowardly refusing push from main."; \
		exit 1; \
	fi

git-on-main:
	@branch=$$(git symbolic-ref --short HEAD); \
	if [ "$$branch" != "main" ]; then \
		echo "Must be on main branch."; \
		exit 1; \
	fi

git-no-unsaved:
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

GITHUB_39 := https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039
FILES_39 := chinese_simplified.txt chinese_traditional.txt czech.txt english.txt \
         french.txt italian.txt japanese.txt korean.txt portuguese.txt spanish.txt

download-wordlists:
	$(foreach file,$(FILES_39),curl -s $(GITHUB_39)/$(file) -o src/bipsea/wordlists/$(file);)
