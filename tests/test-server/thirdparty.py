from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from session import convert_session_to_container  # pylint: disable=import-error
from supertokens_python.recipe.thirdparty.interfaces import (
    EmailChangeNotAllowedError,
    ManuallyCreateOrUpdateUserOkResult,
    SignInUpNotAllowed,
)
from supertokens_python.recipe.thirdparty.syncio import manually_create_or_update_user

from utils import (  # pylint: disable=import-error
    serialize_recipe_user_id,
    serialize_user,
)  # pylint: disable=import-error


def add_thirdparty_routes(app: Flask):
    @app.route("/test/thirdparty/manuallycreateorupdateuser", methods=["POST"])  # type: ignore
    def thirdpartymanuallycreateorupdate():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        third_party_id = data["thirdPartyId"]
        third_party_user_id = data["thirdPartyUserId"]
        email = data["email"]
        is_verified = data["isVerified"]
        user_context = data.get("userContext", {})

        session = None
        if data.get("session"):
            session = convert_session_to_container(data["session"])

        response = manually_create_or_update_user(
            tenant_id,
            third_party_id,
            third_party_user_id,
            email,
            is_verified,
            session,
            user_context,
        )

        if isinstance(response, ManuallyCreateOrUpdateUserOkResult):
            return jsonify(
                {
                    "status": "OK",
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    **serialize_recipe_user_id(
                        response.recipe_user_id, request.headers.get("fdi-version", "")
                    ),
                }
            )
        elif isinstance(response, EmailChangeNotAllowedError):
            return jsonify(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": response.reason}
            )
        elif isinstance(response, SignInUpNotAllowed):
            return jsonify(response.to_json())
        elif isinstance(response, SignInUpNotAllowed):
            return jsonify(response.to_json())
        else:
            return jsonify(
                {
                    "status": response.status,
                    "reason": response.reason,
                }
            )

    @app.route("/test/thirdparty/getprovider", methods=["POST"])  # type: ignore
    def get_provider():  # type: ignore
        data = request.get_json()  # type: ignore
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id: str = data.get("tenantId", "public")
        third_party_id: str = data["thirdPartyId"]
        client_type: Optional[str] = data.get("clientType", None)
        user_context: Dict[str, Any] = data.get("userContext", {})

        from supertokens_python.recipe.thirdparty.syncio import get_provider

        provider = get_provider(tenant_id, third_party_id, client_type, user_context)

        if provider is None:
            return jsonify({})

        return jsonify({"id": provider.id, "config": provider.config.to_json()})
