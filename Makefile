.PHONY: check install install-go lint push test test-network

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

lint:
	isort .
	black .
	actionlint

push: lint check test

test:
	python -m pytest tests -m "not network" -sx

test-network:
	python -m pytest tests
