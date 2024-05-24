.PHONY: test test-on

test:
	python -m pytest tests -m "not network" -x

test-network:
	python -m pytest tests