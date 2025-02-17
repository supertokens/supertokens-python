# Contributing

We're so excited you're interested in helping with SuperTokens! We are happy to help you get started, even if you don't have any previous open-source experience :blush:

## New to Open Source?

1. Take a look at [How to Contribute to an Open Source Project on GitHub](https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github)
2. Go through the [SuperTokens Code of Conduct](https://github.com/supertokens/supertokens-python/blob/master/CODE_OF_CONDUCT.md)

## Where to ask Questions?

1. Check our [Github Issues](https://github.com/supertokens/supertokens-python/issues) to see if someone has already answered your question.
2. Join our community on [Discord](https://supertokens.io/discord) and feel free to ask us your questions

## Development Setup

You will need to setup the [supertokens-core](https://github.com/supertokens/supertokens-core) in order to run the `supertokens-python` tests, you can setup `supertokens-core` by following this [guide](https://github.com/supertokens/supertokens-core/blob/master/CONTRIBUTING.md#development-setup)
**Note: If you are not contributing to the `supertokens-core` you can skip steps 1 & 4 under Project Setup of the `supertokens-core` contributing guide.**

### Prerequisites

-   Python (version 3.7 or above)
-   IDE: [PyCharm](https://www.jetbrains.com/pycharm/download)(recommended) OR [VS Code](https://code.visualstudio.com/) OR equivalent IDE

### Project Setup

1. Fork the [supertokens-python](https://github.com/supertokens/supertokens-python) repository.
2. Clone the forked repository in the parent directory of the previously setup `supertokens-root`.
   `supertokens-python` and `supertokens-root` should exist side by side within the same parent directory.
3. Create a virtual environment for the `supertokens-python` project and activate it.
4. Install the project dependencies
   `make dev-install`
5. Add git pre-commit hooks
   `make set-up-hooks`

## Modifying Code

- Open the `supertokens-python` project in your IDE and you can start modifying the code.
- Use `make lint` to find lint/formatting errors before committing. (They will run anyways)

## Testing

> [!CAUTION]
> These tests run by creating multiple applications on the supertokens-core, and should **not** be run on actual core instances.
> Use the Docker `compose.yml` file to run the required containers for tests.

1. Install `docker`
   1. [Docker Desktop](https://docs.docker.com/desktop/) is convenient to install and use, and includes a Docker Engine.
   2. [Docker Engine](https://docs.docker.com/engine/install/) is the minimum requirement to spin up containers required for tests.
2. To run all tests, use `make test`.
   1. NOTE: This starts up a docker container, and is required for tests to run.
   2. Set `SUPERTOKENS_CORE_VERSION` to pull a certain image, defaults to `latest`.
3. To run individual tests
   1. `docker compose up --wait; pytest ./tests/path/to/test/file.py::test_function_name`
   2. OR use your IDE's in-built UI for running python tests. You may read [VSCode Python Testing](https://code.visualstudio.com/docs/python/testing) and [PyCharm Testing](https://www.jetbrains.com/help/pycharm/testing-your-first-python-application.html#debug-test) for more info.

## Pull Request

1. Before submitting a pull request make sure all tests have passed.
2. Reference the relevant issue or pull request and give a clear description of changes/features added when submitting a pull request.
3. Make sure the PR title follows [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

## SuperTokens Community

SuperTokens is made possible by a passionate team and a strong community of developers. If you have any questions or would like to get more involved in the SuperTokens community you can check out:

-   [Github Issues](https://github.com/supertokens/supertokens-python/issues)
-   [Discord](https://supertokens.io/discord)
-   [Twitter](https://twitter.com/supertokensio)
-   or [email us](mailto:team@supertokens.io)

Additional resources you might find useful:

-   [SuperTokens Docs](https://supertokens.io/docs/community/getting-started/installation)
-   [Blog Posts](https://supertokens.io/blog/)

## Implementing RecipeInterfaces

- Make sure all CRUD operations are available via the `(a)?syncio` modules of that recipe.
- Make sure the corresponding `RecipeImplementation` takes type imports from the `interfaces.py` file of that recipe. This is so that if a user wants to copy / paste that code into their project, they can do so via the normal import statement.

## Implementing APIInterfaces
- Make sure the corresonding `APIImplementation` takes type imports from the `interfaces.py` file of that recipe. This is so that if a user wants to copy / paste that code into their project, they can do so via the normal import statement.

## Generating docs
This will generate the API docs in a folder called docs
```
make build-docs
```
