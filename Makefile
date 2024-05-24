.PHONY: test test-on

test:
	python -m pytest tests -m "not network" -vx

test-network:
	python -m pytest tests