test:
	python -m pytest tests -m "not network" -sv

test-on:
	python -m pytest tests