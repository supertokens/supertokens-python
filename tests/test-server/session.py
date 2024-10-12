from typing import Any, Dict
from flask import Flask, request, jsonify
from override_logging import log_override_event  # pylint: disable=import-error
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.interfaces import TokenInfo
from supertokens_python.recipe.session.jwt import (
    parse_jwt_without_signature_verification,
)
from supertokens_python.types import RecipeUserId
from utils import (  # pylint: disable=import-error
    deserialize_validator,
    get_max_version,
)
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe.session.session_class import Session
import supertokens_python.recipe.session.syncio as session
from utils import deserialize_claim  # pylint: disable=import-error


def add_session_routes(app: Flask):
    @app.route("/test/session/createnewsessionwithoutrequestresponse", methods=["POST"])  # type: ignore
    def create_new_session_without_request_response():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        from supertokens_python import convert_to_recipe_user_id

        fdi_version = request.headers.get("fdi-version")
        assert fdi_version is not None
        if get_max_version("1.17", fdi_version) == "1.17" or (
            get_max_version("2.0", fdi_version) == fdi_version
            and get_max_version("3.0", fdi_version) != fdi_version
        ):
            # fdi_version <= "1.17" or (fdi_version >= "2.0" and fdi_version < "3.0")
            recipe_user_id = convert_to_recipe_user_id(data["userId"])
        else:
            recipe_user_id = convert_to_recipe_user_id(data["recipeUserId"])
        access_token_payload = data.get("accessTokenPayload", {})
        session_data_in_database = data.get("sessionDataInDatabase", {})
        disable_anti_csrf = data.get("disableAntiCsrf")
        user_context = data.get("userContext", {})

        session_container = session.create_new_session_without_request_response(
            tenant_id,
            recipe_user_id,
            access_token_payload,
            session_data_in_database,
            disable_anti_csrf,
            user_context,
        )

        return jsonify(convert_session_to_json(session_container))

    @app.route("/test/session/getsessionwithoutrequestresponse", methods=["POST"])  # type: ignore
    def get_session_without_request_response():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        access_token = data["accessToken"]
        anti_csrf_token = data.get("antiCsrfToken")
        options = data.get("options")
        user_context = data.get("userContext", {})

        session_container = session.get_session_without_request_response(
            access_token, anti_csrf_token, options, user_context
        )
        return jsonify(
            None
            if session_container is None
            else convert_session_to_json(session_container)
        )

    @app.route("/test/session/sessionobject/assertclaims", methods=["POST"])  # type: ignore
    def assert_claims():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        session_container = convert_session_to_container(data)
        claim_validators = list(map(deserialize_validator, data["claimValidators"]))

        user_context = data.get("userContext", {})

        try:
            session_container.sync_assert_claims(claim_validators, user_context)
            return jsonify(
                {
                    "status": "OK",
                    "updatedSession": convert_session_to_json(session_container),
                }
            )
        except Exception as e:
            raise e
            # return jsonify({"status": "ERROR", "message": str(e)}), 500

    @app.route(  # type: ignore
        "/test/session/sessionobject/mergeintoaccesstokenpayload", methods=["POST"]
    )  # type: ignore
    def merge_into_access_token_payload_on_session_object():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        session_container = convert_session_to_container(data)

        access_token_payload_update = data["accessTokenPayloadUpdate"]
        user_context = data.get("userContext", {})

        session_container.sync_merge_into_access_token_payload(
            access_token_payload_update, user_context
        )

        return jsonify(
            {
                "status": "OK",
                "updatedSession": convert_session_to_json(session_container),
            }
        )

    @app.route("/test/session/getsessioninformation", methods=["POST"])  # type: ignore
    def get_session_information_api():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        session_handle = data["sessionHandle"]
        user_context = data.get("userContext", {})

        response = session.get_session_information(session_handle, user_context)
        if response is None:
            return jsonify(None)
        return jsonify(
            {
                "customClaimsInAccessTokenPayload": response.custom_claims_in_access_token_payload,
                "sessionDataInDatabase": response.session_data_in_database,
                "expiry": response.expiry,
                "sessionHandle": response.session_handle,
                "recipeUserId": response.recipe_user_id.get_as_string(),
                "tenantId": response.tenant_id,
                "timeCreated": response.time_created,
                "userId": response.user_id,
            }
        )

    @app.route("/test/session/sessionobject/fetchandsetclaim", methods=["POST"])  # type: ignore
    def fetch_and_set_claim_api():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        log_override_event("sessionobject.fetchandsetclaim", "CALL", data)
        session = convert_session_to_container(data)

        claim = deserialize_claim(data["claim"])
        user_context = data.get("userContext", {})

        session.sync_fetch_and_set_claim(claim, user_context)
        response = {"updatedSession": convert_session_to_json(session)}
        return jsonify(response)

    @app.route("/test/session/sessionobject/getclaimvalue", methods=["POST"])  # type: ignore
    def get_claim_value_api():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        log_override_event("sessionobject.getclaimvalue", "CALL", data)
        session = convert_session_to_container(data)

        claim = deserialize_claim(data["claim"])
        user_context = data.get("userContext", {})

        try:
            ret_val = session.sync_get_claim_value(claim, user_context)
            response = {
                "retVal": ret_val,
                "updatedSession": convert_session_to_json(session),
            }
            log_override_event("sessionobject.getclaimvalue", "RES", ret_val)
            return jsonify(response)
        except Exception as e:
            log_override_event("sessionobject.getclaimvalue", "REJ", str(e))
            raise e


def convert_session_to_json(session_container: SessionContainer) -> Dict[str, Any]:
    return {
        "sessionHandle": session_container.get_handle(),
        "userId": session_container.get_user_id(),
        "tenantId": session_container.get_tenant_id(),
        "userDataInAccessToken": session_container.get_access_token_payload(),
        "accessToken": session_container.get_access_token(),
        "frontToken": session_container.get_all_session_tokens_dangerously()[
            "frontToken"
        ],
        "refreshToken": session_container.get_all_session_tokens_dangerously()[
            "refreshToken"
        ],
        "antiCsrfToken": session_container.get_all_session_tokens_dangerously()[
            "antiCsrfToken"
        ],
        "accessTokenUpdated": session_container.get_all_session_tokens_dangerously()[
            "accessAndFrontTokenUpdated"
        ],
        "recipeUserId": {
            # this is intentionally done this way cause the test in the test suite expects this way.
            "recipeUserId": session_container.get_recipe_user_id().get_as_string()
        },
    }


def convert_session_to_container(data: Any) -> Session:
    jwt_info = parse_jwt_without_signature_verification(data["session"]["accessToken"])
    jwt_payload = jwt_info.payload

    user_id = jwt_payload["userId"] if jwt_info.version == 2 else jwt_payload["sub"]
    session_handle = jwt_payload["sessionHandle"]

    recipe_user_id = RecipeUserId(jwt_payload.get("rsub", user_id))
    anti_csrf_token = jwt_payload.get("antiCsrfToken")
    tenant_id = jwt_payload["tId"] if jwt_info.version >= 4 else "public"

    return Session(
        recipe_implementation=SessionRecipe.get_instance().recipe_implementation,
        config=SessionRecipe.get_instance().config,
        access_token=data["session"]["accessToken"],
        front_token=data["session"]["frontToken"],
        refresh_token=(
            TokenInfo(
                (
                    data["session"]["refreshToken"]
                    if isinstance(data["session"]["refreshToken"], str)
                    else data["session"]["refreshToken"]["token"]
                ),
                (
                    -1
                    if isinstance(data["session"]["refreshToken"], str)
                    else data["session"]["refreshToken"]["expiry"]
                ),
                (
                    -1
                    if isinstance(data["session"]["refreshToken"], str)
                    else data["session"]["refreshToken"]["createdTime"]
                ),
            )
            if "refreshToken" in data["session"]
            and data["session"]["refreshToken"] is not None
            else None
        ),
        anti_csrf_token=anti_csrf_token,
        session_handle=session_handle,
        user_id=user_id,
        recipe_user_id=recipe_user_id,
        user_data_in_access_token=jwt_payload,
        req_res_info=None,  # We don't have this information in the input
        access_token_updated=False,
        tenant_id=tenant_id,
    )
