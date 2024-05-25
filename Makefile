.PHONY: check lint test test-on

check:
	black . --check

install:
	pip install -r requirements.txt -r test-requirements.txt
lint:
	black .

test:
	python -m pytest tests -m "not network" -x

test-network:
	python -m pytest tests