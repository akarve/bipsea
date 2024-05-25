.PHONY: check install lint test test-on

check:
	black . --check

# developer
install-dev:
	pip install -r requirements.txt -r test-requirements.txt
	pip install -e .
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest

lint:
	black .

test:
	pytest tests -m "not network" -x

test-network:
	o tytest tests