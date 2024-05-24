.PHONY: test test-on

test:
	python -m pytest tests -m "not network" -sxv

test-network:
	python -m pytest tests