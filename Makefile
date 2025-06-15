help:
	@echo "        \x1b[33;1mtest: \x1b[0mruns pytest"
	@echo "        \x1b[33;1mlint: \x1b[0mrun all hooks - lint and format code"
	@echo "\x1b[33;1mset-up-hooks: \x1b[0mset up various git hooks"
	@echo " \x1b[33;1mdev-install: \x1b[0minstall all packages required for development"
	@echo "        \x1b[33;1mhelp: \x1b[0mprints this"

lint:
	pre-commit run --all-files
	pre-commit run --all-files --hook-stage manual pyright

set-up-hooks:
	pre-commit install

test:
	docker compose up --wait
	pytest -vv ./tests/ --junit-xml=test-results/junit.xml $(ARGS)
	docker compose down

dev-install:
	pip install -r dev-requirements.txt

freeze-dev-requirements:
	pip freeze > dev-requirements.txt

with-fastapi:
	pip3 install -e .[fastapi]

with-litestar:
	pip3 install -e .[litestar]

with-django:
	pip3 install -e .[django]

with-django2x:
	pip3 install -e .[django2x]

with-drf:
	pip3 install -e .[drf]

with-flask:
	pip3 install -e .[flask]

build-docs:
	rm -rf html && pdoc --html supertokens_python --template-dir docs-templates
