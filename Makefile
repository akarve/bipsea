.PHONY: all clean install test

all:: install build

test:: lint test-ci

test-ci::
	poetry run pytest -sx

test-dist:: clean build install-dist readme-cmds

push:: test readme-cmds git-off-main git-no-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

build: install-local
	poetry build

download-wordlists:: cmd-env
	$(foreach file,$(FILES_39),curl -s $(GITHUB_39)/$(file) -o src/bipsea/wordlists/$(file);)

clean::
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache
	poetry run pip uninstall -y bipsea

publish:: download-wordlists git-no-unsaved git-on-main test-dist install test
	poetry publish

install:: install-ci install-go

install-ci:: install-local
	poetry install --only dev

install-local::
	poetry install

install-go::
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest
	go install github.com/mrtazz/checkmake/cmd/checkmake@latest

install-dist::
	pip3 install dist/*.whl 

check::
	poetry run black . --check
	poetry run isort . --check
	poetry run flake8 . --ignore=E501,W503

lint::
	poetry run isort .
	poetry run black .
	poetry run actionlint
	poetry run flake8 . --ignore=E501,W503
	poetry run checkmake Makefile

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

cmd-env::
	$(eval MNEMONIC="elder major green sting survey canoe inmate funny bright jewel anchor volcano")
	$(eval GITHUB_39=https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039)
	$(eval FILES_39=chinese_simplified.txt chinese_traditional.txt czech.txt english.txt french.txt italian.txt japanese.txt korean.txt portuguese.txt spanish.txt)

REDIRECT_TO ?= > /dev/null
readme-cmds:: cmd-env
	bipsea --version $(REDIRECT_TO)

	bipsea --help $(REDIRECT_TO)
	bipsea mnemonic --help $(REDIRECT_TO)
	bipsea validate --help $(REDIRECT_TO)
	bipsea xprv --help $(REDIRECT_TO)
	bipsea derive --help $(REDIRECT_TO)

	bipsea mnemonic | bipsea validate | bipsea xprv | bipsea derive -a mnemonic -n 12 $(REDIRECT_TO)

	bipsea mnemonic -t jpn -n 15 $(REDIRECT_TO)
	bipsea mnemonic -t eng -n 12 --pretty $(REDIRECT_TO)
	bipsea mnemonic -t spa -n 12 | bipsea validate -f spa $(REDIRECT_TO)

	bipsea mnemonic | bipsea validate | bipsea xprv $(REDIRECT_TO)

	bipsea validate -f free -m "123456123456123456" | bipsea xprv $(REDIRECT_TO)
	bipsea validate -f free -m @"$$(cat input.txt)" $(REDIRECT_TO)

	bipsea validate -m $(MNEMONIC) | bipsea xprv | bipsea derive -a mnemonic -t jpn -n 12 $(REDIRECT_TO)
	bipsea validate -m $(MNEMONIC) | bipsea xprv | bipsea derive -a mnemonic -t jpn -n 12 -i 1 $(REDIRECT_TO)
	bipsea validate -m $(MNEMONIC) | bipsea xprv | bipsea derive -a drng -n 1000 $(REDIRECT_TO)
	bipsea validate -m $(MNEMONIC) | bipsea xprv | bipsea derive -a dice -n 10 -s 6 $(REDIRECT_TO)
	bipsea validate -m $(MNEMONIC) | bipsea xprv | bipsea derive -a dice -n 6 $(REDIRECT_TO)
