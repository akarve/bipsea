.PHONY: all clean install test

all:: install build

test:: lint test-ci

test-ci::
	poetry run pytest tests -sx

test-dist:: clean build install-dist readme-cmds

push:: test readme-cmds git-off-main git-no-unsaved
	@branch=$$(git symbolic-ref --short HEAD); \
	git push origin $$branch

build: install-ci
	poetry build

download-wordlists:: cmd-env
	$(foreach file,$(FILES_39),curl -s $(GITHUB_39)/$(file) -o src/bipsea/wordlists/$(file);)

clean::
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info .pytest_cache
	pip uninstall -y bipsea

publish:: download-wordlists git-no-unsaved git-on-main test-dist install test
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

cmd-env::
	$(eval MNEMONIC="elder major green sting survey canoe inmate funny bright jewel anchor volcano")
	$(eval GITHUB_39=https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039)
	$(eval FILES_39=chinese_simplified.txt chinese_traditional.txt czech.txt english.txt french.txt italian.txt japanese.txt korean.txt portuguese.txt spanish.txt)

REDIRECT_TO ?= > /dev/null
readme-cmds:: cmd-env
	poetry run bipsea --version $(REDIRECT_TO)

	poetry run bipsea --help $(REDIRECT_TO)
	poetry run bipsea mnemonic --help $(REDIRECT_TO)
	poetry run bipsea validate --help $(REDIRECT_TO)
	poetry run bipsea xprv --help $(REDIRECT_TO)
	poetry run bipsea derive --help $(REDIRECT_TO)

	poetry run bipsea mnemonic | poetry run bipsea validate | poetry run bipsea xprv | poetry run bipsea derive -a mnemonic -n 12 $(REDIRECT_TO)
	poetry run bipsea mnemonic -t jpn -n 15 $(REDIRECT_TO)
	poetry run bipsea mnemonic -t eng -n 12 --pretty $(REDIRECT_TO)
	poetry run bipsea mnemonic -t spa -n 12 | poetry run bipsea validate -f spa $(REDIRECT_TO)

	poetry run bipsea mnemonic | poetry run bipsea validate | poetry run bipsea xprv $(REDIRECT_TO)

	poetry run bipsea validate -f free -m "123456123456123456" | poetry run bipsea xprv $(REDIRECT_TO)
	poetry run bipsea validate -f free -m @"$$(cat input.txt)" $(REDIRECT_TO)

	poetry run bipsea validate -m $(MNEMONIC) | poetry run bipsea xprv | poetry run bipsea derive -a mnemonic -t jpn -n 12 $(REDIRECT_TO)
	poetry run bipsea validate -m $(MNEMONIC) | poetry run bipsea xprv | poetry run bipsea derive -a mnemonic -t jpn -n 12 -i 1 $(REDIRECT_TO)
	poetry run bipsea validate -m $(MNEMONIC) | poetry run bipsea xprv | poetry run bipsea derive -a drng -n 1000 $(REDIRECT_TO)
	poetry run bipsea validate -m $(MNEMONIC) | poetry run bipsea xprv | poetry run bipsea derive -a dice -n 10 -s 6 $(REDIRECT_TO)
	poetry run bipsea validate -m $(MNEMONIC) | poetry run bipsea xprv | poetry run bipsea derive -a dice -n 6 $(REDIRECT_TO)
