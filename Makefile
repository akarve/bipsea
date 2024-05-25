.PHONY: check install install-go lint test test-on

check:
	black . --check

install-dev:
	pip install -r requirements.txt -r test-requirements.txt
	pip install -e .

install-go
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest

lint:
	black .

test:
	pytest tests -m "not network" -x

test-network:
	pytest tests