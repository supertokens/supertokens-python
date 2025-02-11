from typing import List

from flask import Flask, jsonify, request
from supertokens_python import async_to_sync_wrapper
from supertokens_python.recipe.multifactorauth.types import MFAClaimValue
from supertokens_python.types import User


def add_multifactorauth_routes(app: Flask):
    @app.route("/test/multifactorauthclaim/fetchvalue", methods=["POST"])  # type: ignore
    def fetch_value_api():  # type: ignore
        from supertokens_python import convert_to_recipe_user_id
        from supertokens_python.recipe.multifactorauth.multi_factor_auth_claim import (
            MultiFactorAuthClaim,
        )

        assert request.json is not None
        response: MFAClaimValue = async_to_sync_wrapper.sync(  # type: ignore
            MultiFactorAuthClaim.fetch_value(  # type: ignore
                request.json["_userId"],
                convert_to_recipe_user_id(request.json["recipeUserId"]),
                request.json["tenantId"],
                request.json["currentPayload"],
                request.json.get("userContext"),
            )
        )
        return jsonify(
            {
                "c": response.c,  # type: ignore
                "v": response.v,  # type: ignore
            }
        )

    @app.route("/test/multifactorauth/getfactorssetupforuser", methods=["POST"])  # type: ignore
    def get_factors_setup_for_user_api():  # type: ignore
        from supertokens_python.recipe.multifactorauth.syncio import (
            get_factors_setup_for_user,
        )

        assert request.json is not None
        user_id = request.json["userId"]
        user_context = request.json.get("userContext")

        response = get_factors_setup_for_user(
            user_id=user_id,
            user_context=user_context,
        )
        return jsonify(response)

    @app.route(
        "/test/assertallowedtosetupfactorelsethowinvalidclaimerror", methods=["POST"]
    )  # type: ignore
    def assert_allowed_to_setup_factor_else_throw_invalid_claim_error_api():  # type: ignore
        from session import convert_session_to_container
        from supertokens_python.recipe.multifactorauth.syncio import (
            assert_allowed_to_setup_factor_else_throw_invalid_claim_error,
        )

        assert request.json is not None

        session = None
        if request.json.get("session"):
            session = convert_session_to_container(request.json)
        assert session is not None

        assert_allowed_to_setup_factor_else_throw_invalid_claim_error(
            session=session,
            factor_id=request.json["factorId"],
            user_context=request.json.get("userContext"),
        )

        return "", 200

    @app.route("/test/multifactorauth/getmfarequirementsforauth", methods=["POST"])  # type: ignore
    def get_mfa_requirements_for_auth_api():  # type: ignore
        from session import convert_session_to_container
        from supertokens_python.recipe.multifactorauth.syncio import (
            get_mfa_requirements_for_auth,
        )

        assert request.json is not None

        session = None
        if request.json.get("session"):
            session = convert_session_to_container(request.json)
        assert session is not None

        response = get_mfa_requirements_for_auth(
            session=session,
            user_context=request.json.get("userContext"),
        )

        return jsonify(response)

    @app.route("/test/multifactorauth/markfactorascompleteinsession", methods=["POST"])  # type: ignore
    def mark_factor_as_complete_in_session_api():  # type: ignore
        from session import convert_session_to_container
        from supertokens_python.recipe.multifactorauth.syncio import (
            mark_factor_as_complete_in_session,
        )

        assert request.json is not None

        session = None
        if request.json.get("session"):
            session = convert_session_to_container(request.json)
        assert session is not None

        mark_factor_as_complete_in_session(
            session=session,
            factor_id=request.json["factorId"],
            user_context=request.json.get("userContext"),
        )

        return "", 200

    @app.route(
        "/test/multifactorauth/getrequiredsecondaryfactorsforuser", methods=["POST"]
    )  # type: ignore
    def get_required_secondary_factors_for_user_api():  # type: ignore
        from supertokens_python.recipe.multifactorauth.syncio import (
            get_required_secondary_factors_for_user,
        )

        assert request.json is not None

        response = get_required_secondary_factors_for_user(
            user_id=request.json["userId"],
            user_context=request.json.get("userContext"),
        )

        return jsonify(response)

    @app.route(
        "/test/multifactorauth/addtorequiredsecondaryfactorsforuser", methods=["POST"]
    )  # type: ignore
    def add_to_required_secondary_factors_for_user_api():  # type: ignore
        from supertokens_python.recipe.multifactorauth.syncio import (
            add_to_required_secondary_factors_for_user,
        )

        assert request.json is not None

        add_to_required_secondary_factors_for_user(
            user_id=request.json["userId"],
            factor_id=request.json["factorId"],
            user_context=request.json.get("userContext"),
        )

        return "", 200

    @app.route(
        "/test/multifactorauth/removefromrequiredsecondaryfactorsforuser",
        methods=["POST"],
    )  # type: ignore
    def remove_from_required_secondary_factors_for_user_api():  # type: ignore
        from supertokens_python.recipe.multifactorauth.syncio import (
            remove_from_required_secondary_factors_for_user,
        )

        assert request.json is not None

        remove_from_required_secondary_factors_for_user(
            user_id=request.json["userId"],
            factor_id=request.json["factorId"],
            user_context=request.json.get("userContext"),
        )

        return "", 200

    @app.route(
        "/test/multifactorauth/recipeimplementation.getmfarequirementsforauth",
        methods=["POST"],
    )  # type: ignore
    def get_mfa_requirements_for_auth_api2():  # type: ignore
        assert request.json is not None
        from supertokens_python.recipe.multifactorauth.recipe import (
            MultiFactorAuthRecipe,
        )

        async def user() -> User:
            assert request.json is not None
            user_json = request.json["user"]
            assert user_json is not None
            return User.from_json(user_json)

        async def factors_set_up_for_user() -> List[str]:
            assert request.json is not None
            return request.json["factorsSetUpForUser"]

        async def required_secondary_factors_for_user() -> List[str]:
            assert request.json is not None
            return request.json["requiredSecondaryFactorsForUser"]

        async def required_secondary_factors_for_tenant() -> List[str]:
            assert request.json is not None
            return request.json["requiredSecondaryFactorsForTenant"]

        response = async_to_sync_wrapper.sync(
            MultiFactorAuthRecipe.get_instance_or_throw_error().recipe_implementation.get_mfa_requirements_for_auth(
                tenant_id=request.json["tenantId"],
                access_token_payload=request.json["accessTokenPayload"],
                completed_factors=request.json["completedFactors"],
                user=user,
                factors_set_up_for_user=factors_set_up_for_user,
                required_secondary_factors_for_user=required_secondary_factors_for_user,
                required_secondary_factors_for_tenant=required_secondary_factors_for_tenant,
                user_context=request.json.get("userContext"),
            )
        )

        return jsonify(response)
