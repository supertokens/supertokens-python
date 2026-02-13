help:
	@echo "        \x1b[33;1mtest: \x1b[0mruns pytest"
	@echo "        \x1b[33;1mlint: \x1b[0mrun all hooks - lint and format code"
	@echo "\x1b[33;1mset-up-hooks: \x1b[0mset up various git hooks"
	@echo " \x1b[33;1mdev-install: \x1b[0minstall all packages required for development"
	@echo "        \x1b[33;1mhelp: \x1b[0mprints this"

lint:
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit run --all-files; \
		pre-commit run --all-files --hook-stage manual pyright; \
	elif docker compose ps --status running mcp 2>/dev/null | grep -q mcp; then \
		docker compose exec -T -w /workspace mcp pre-commit run --all-files; \
		docker compose exec -T -w /workspace mcp pre-commit run --all-files --hook-stage manual pyright; \
	else \
		echo "ERROR: Cannot run linters. Install pre-commit locally or start the MCP container (docker compose up -d mcp)." >&2; \
		exit 1; \
	fi

set-up-hooks:
	cp hooks/pre-commit-docker.sh .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

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
