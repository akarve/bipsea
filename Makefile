test:
	python -m pytest tests -m "not network" -svx

test-on:
	python -m pytest tests