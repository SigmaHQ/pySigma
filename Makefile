test:
	python -m pytest --cov=sigma -vv

covreport:
	python -m pytest --cov=sigma --cov-report xml:cov.xml

build:
	poetry build