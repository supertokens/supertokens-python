help:
	@echo "  \x1b[33;1mcheck-lint: \x1b[0mtest styling of code for the library using flak8"
	@echo "        \x1b[33;1mtest: \x1b[0mruns pytest"
	@echo "        \x1b[33;1mlint: \x1b[0mformat code using black"
	@echo "\x1b[33;1mset-up-hooks: \x1b[0mset up various git hooks"
	@echo " \x1b[33;1mdev-install: \x1b[0minstall all packages required for development"
	@echo "        \x1b[33;1mhelp: \x1b[0mprints this"

format:
	black .

check-lint:
	pyright supertokens_python tests examples && pylint supertokens_python tests examples 

set-up-hooks:
	cp hooks/pre-commit.sh .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

test:
	pytest -vv --reruns 3 --reruns-delay 5 ./tests/

dev-install:
	pip install -r dev-requirements.txt

freeze-dev-requirements:
	pip freeze > dev-requirements.txt

with-fastapi:
	pip3 install -e .[fastapi]

with-django:
	pip3 install -e .[django]

with-django2x:
	pip3 install -e .[django2x]

with-drf:
	pip3 install -e .[drf]

with-flask:
	pip3 install -e .[flask]

with-litestar:
	pip3 install -e .[litestar]

build-docs:
	rm -rf html && pdoc --html supertokens_python --template-dir docs-templates