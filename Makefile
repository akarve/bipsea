test:
	python -m pytest tests/test.py -m "not network" -sx

test-on:
	python -m pytest tests/test.py