.PHONY: check install lint test test-on

check:
	black . --check

# developer
install:
	pip install -r requirements.txt -r test-requirements.txt
	# you must have go installed https://go.dev/doc/install	
	go install github.com/rhysd/actionlint/cmd/actionlint@latest

lint:
	black .

test:
	python -m pytest tests -m "not network" -x

test-network:
	python -m pytest tests