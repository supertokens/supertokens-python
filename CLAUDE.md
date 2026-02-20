# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Python SDK for SuperTokens authentication platform. Provides recipe-based auth features (session, emailpassword, passwordless, thirdparty, MFA, OAuth2, WebAuthn, etc.) with framework adapters for FastAPI, Flask, and Django.

## Commands

```bash
# Install dev dependencies
make dev-install

# Install framework-specific extras
make with-fastapi   # or with-flask, with-django, with-drf

# Run all tests (starts Docker containers for SuperTokens Core + OAuth2 provider)
make test

# Run specific test file or test function (Docker must be running)
docker compose up --wait
pytest ./tests/path/to/test_file.py
pytest ./tests/path/to/test_file.py::test_function_name

# Lint and type-check
make lint

# Set up git hooks
make set-up-hooks
```

## Architecture

### Recipe Pattern

Every auth feature is a **recipe** under `supertokens_python/recipe/<name>/`. Each recipe follows the same structure:

- `recipe.py` — Singleton recipe class extending `RecipeModule`. Entry point for initialization.
- `interfaces.py` — `RecipeInterface` (backend logic customization) and `APIInterface` (endpoint customization). These are the override points users interact with.
- `recipe_implementation.py` — Default implementation of `RecipeInterface`, calls SuperTokens Core via `Querier`.
- `api/` — HTTP endpoint handlers implementing `APIInterface`.
- `exceptions.py` — Recipe-specific exception types.
- `asyncio/` and `syncio/` — Public-facing async and sync function wrappers.

### Async-First with Sync Wrappers

All core logic is async. Sync versions exist under `syncio/` directories and use `async_to_sync_wrapper.py`. Tests use `asyncio_mode = "auto"` so no `@pytest.mark.asyncio` decorator is needed.

### Framework Adapters

`supertokens_python/framework/{django,fastapi,flask}/` — Each provides middleware and request/response wrappers that adapt to the framework's native objects, inheriting from `BaseRequest`/`BaseResponse`.

### Core Communication

`Querier` handles all HTTP communication with the SuperTokens Core service. Recipes call `Querier` methods rather than making HTTP requests directly.

### Type System

Uses Pydantic v2 models. API response classes must inherit from `APIResponse` and implement `to_json()`. Pyright is configured in strict mode.

## Code Style Conventions

- **snake_case** for variables/functions, **PascalCase** for classes
- Import `Literal` from `typing_extensions`, not `typing`
- Use `Union[X, Y]` instead of `X | Y` for type unions
- Avoid `TypedDict` — use Pydantic models or plain `Dict`
- Use generic `Dict` only for `user_context` parameters
- One unique status class per unique status string in function outputs
- API interface output classes must inherit `APIResponse` with a `to_json()` method
- Semantics must match the TypeScript SDK (this is a port of `supertokens-node`)

## Testing

Tests require Docker (SuperTokens Core + OAuth2 test provider via `compose.yml`). The `conftest.py` auto-fixture calls `reset()` before and after each test to clear singleton state. Test helpers are in `tests/utils.py`.

## Version Management

`setup.py` version and `supertokens_python/constants.py` `VERSION` must stay in sync — enforced by a pre-commit hook (`check-version.sh`).
