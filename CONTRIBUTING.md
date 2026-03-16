# Contributing

We're so excited you're interested in helping with SuperTokens! We are happy to help you get started, even if you don't have any previous open-source experience :blush:

## New to Open Source?

1. Take a look at [How to Contribute to an Open Source Project on GitHub](https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github)
2. Go through the [SuperTokens Code of Conduct](https://github.com/supertokens/supertokens-python/blob/master/CODE_OF_CONDUCT.md)

## Where to ask Questions?

1. Check our [Github Issues](https://github.com/supertokens/supertokens-python/issues) to see if someone has already answered your question.
2. Join our community on [Discord](https://supertokens.io/discord) and feel free to ask us your questions

## Development Setup

### Prerequisites

- Python 3.8 or above
- [Docker](https://docs.docker.com/desktop/) (required to run tests)
- IDE: [PyCharm](https://www.jetbrains.com/pycharm/download) (recommended) or [VS Code](https://code.visualstudio.com/)
- [changie](https://changie.dev/guide/installation/) (required to add changelog entries)
  ```bash
  brew install changie   # macOS
  # or download a binary from https://github.com/miniscruff/changie/releases
  ```

### Project Setup

1. Fork and clone [supertokens-python](https://github.com/supertokens/supertokens-python).
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   ```
3. Install project dependencies:
   ```bash
   make dev-install
   ```
4. Install framework-specific extras if needed:
   ```bash
   make with-fastapi   # or with-flask, with-django, with-drf
   ```
5. Set up git hooks (enforces version sync between `setup.py` and `constants.py`):
   ```bash
   make set-up-hooks
   ```

## Modifying Code

- Open the project in your IDE and start modifying.
- Run `make lint` to check for lint/type errors before committing (the pre-commit hook also runs this).

## Testing

> [!CAUTION]
> Tests create multiple applications on the SuperTokens core and **must not** be run against production instances. Use the Docker `compose.yml` provided.

1. Run all tests (starts required containers automatically):
   ```bash
   make test
   ```
   Set `SUPERTOKENS_CORE_VERSION` to test against a specific core version (defaults to `latest`).

2. Run a specific test file or function:
   ```bash
   docker compose up --wait
   pytest ./tests/path/to/test_file.py
   pytest ./tests/path/to/test_file.py::test_function_name
   ```
   You can also use your IDE's built-in test runner:
   [VS Code Python Testing](https://code.visualstudio.com/docs/python/testing) |
   [PyCharm Testing](https://www.jetbrains.com/help/pycharm/testing-your-first-python-application.html)

## Changelog

Every pull request must include a changelog fragment describing the change. We use [changie](https://changie.dev) to manage changelog entries.

### Adding a fragment

Run the following command from the repo root and follow the prompts:

```bash
changie new
```

This creates a small YAML file under `.changes/unreleased/`. Commit this file with your changes — CI will check that it exists.

**Kinds to choose from:**

| Kind | When to use |
|---|---|
| `Added` | New feature or capability |
| `Changed` | Change to existing behaviour |
| `Fixed` | Bug fix |
| `Breaking Changes` | Anything that breaks backwards compatibility |
| `Infrastructure` | CI, tooling, dependency changes |
| `Deprecated` | Something that will be removed in a future version |
| `Removed` | Removal of a feature |
| `Security` | Security fix |

### Skipping the changelog check

If a PR has no user-facing impact (e.g., a documentation typo fix or test refactor), add the `Skip-Changelog` label on GitHub to bypass the check.

## Pull Request

1. Make sure all tests pass before submitting.
2. Reference the relevant issue and give a clear description of the changes.
3. Ensure the PR title follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (enforced by CI).
4. Include a changelog fragment (see [Changelog](#changelog) above) or add the `Skip-Changelog` label.

## Implementing RecipeInterfaces

- Make sure all CRUD operations are available via the `(a)?syncio` modules of that recipe.
- Make sure the corresponding `RecipeImplementation` takes type imports from the `interfaces.py` file of that recipe. This allows users to copy/paste that code into their project with standard imports.

## Implementing APIInterfaces

- Make sure the corresponding `APIImplementation` takes type imports from the `interfaces.py` file of that recipe. This allows users to copy/paste that code into their project with standard imports.

## Generating Docs

```bash
make build-docs
```

This generates API docs in a `html/` folder.

## SuperTokens Community

SuperTokens is made possible by a passionate team and a strong community of developers. If you have any questions or would like to get more involved:

- [Github Issues](https://github.com/supertokens/supertokens-python/issues)
- [Discord](https://supertokens.io/discord)
- [Twitter](https://twitter.com/supertokensio)
- [Email us](mailto:team@supertokens.io)

Additional resources:

- [SuperTokens Docs](https://supertokens.io/docs/community/getting-started/installation)
- [Blog Posts](https://supertokens.io/blog/)
