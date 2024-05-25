.PHONY: check install-dev install-go lint test test-network

check:
	black . --check

install-dev:
	pip install -r requirements.txt -r test-requirements.txt
	pip install -e .

install-go:
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest

lint:
	black .
	actionlint

test:
	python -m pytest tests -m "not network" -vx

test-network:
	python -m pytest tests