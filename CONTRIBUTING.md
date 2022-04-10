# Contributing

We're so excited you're interested in helping with SuperTokens! We are happy to help you get started, even if you don't have any previous open-source experience :blush:

## New to Open Source?

1. Take a look at [How to Contribute to an Open Source Project on GitHub](https://egghead.io/courses/how-to-contribute-to-an-open-source-project-on-github)
2. Go through the [SuperTokens Code of Conduct](https://github.com/supertokens/supertokens-python/blob/master/CODE_OF_CONDUCT.md)

## Where to ask Questions?

1. Check our [Github Issues](https://github.com/supertokens/supertokens-python/issues) to see if someone has already answered your question.
2. Join our community on [Discord](https://supertokens.io/discord) and feel free to ask us your questions

## Development Setup

You will need to setup the `supertokens-core` in order to run the `supertokens-python` tests, you can setup `supertokens-core` by following this [guide](https://github.com/supertokens/supertokens-core/blob/master/CONTRIBUTING.md#development-setup)  
**Note: If you are not contributing to the `supertokens-core` you can skip steps 1 & 4 under Project Setup of the `supertokens-core` contributing guide.**

### Prerequisites

-   Python (version 3.7 or above)
-   IDE: [vscode](https://code.visualstudio.com/)(recommended) or equivalent IDE

### Project Setup

- Fork the `supertokens-python` repository on github.
- Clone the repository you that just forked into your account.
    ```
    git clone git@github.com:<your user name>/supertokens-python.git
    ```
- On a local machine create a [virtual env](https://docs.python.org/3/library/venv.html)
- Activate the virtual env
- Go to `supertokens-python` directory from the terminal
    ```
    cd supertokens-python
    ```
- Install the dependencies with following command
   ```
   make dev-install
   ```

## Modifying Code

- Configure `pre-commit` hooks
    ```
    make set-up-hooks
    ```
- Once the code modifications are done, make sure to fix the code formatting with
    ```
    make format 
    ```
- To generate the documentation, run
    ```
    make build-docs
    ```

- Make sure to update/add API documentation after modifying the code.
- Make sure to update/add tests after modifying the code.

## Testing

- To run the tests, run
    ```
    make test
    ```

## Pull Request

1. Before submitting a pull request make sure all tests have passed
2. Reference the relevant issue or pull request and give a clear description of changes/features added when submitting a pull request
3. Make sure the PR title follows [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) specification

## SuperTokens Community

SuperTokens is made possible by a passionate team and a strong community of developers. If you have any questions or would like to get more involved in the SuperTokens community you can check out:

-   [Github Issues](https://github.com/supertokens/supertokens-python/issues)
-   [Discord](https://supertokens.io/discord)
-   [Twitter](https://twitter.com/supertokensio)
-   or [email us](mailto:team@supertokens.io)

Additional resources you might find useful:

-   [SuperTokens Docs](https://supertokens.io/docs/community/getting-started/installation)
-   [Blog Posts](https://supertokens.io/blog/)