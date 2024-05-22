.PHONY: test test-on

test:
	python -m pytest tests -m "not network" -sv

test-network:
	python -m pytest tests