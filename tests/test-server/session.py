from flask import Flask, request, jsonify
from utils import deserialize_validator
from supertokens_python import async_to_sync_wrapper
from supertokens_python.recipe.session.recipe import SessionRecipe
from supertokens_python.recipe.session.session_class import Session
import supertokens_python.recipe.session.syncio as session


def add_session_routes(app: Flask):
    @app.route("/test/session/createnewsessionwithoutrequestresponse", methods=["POST"])  # type: ignore
    def create_new_session_without_request_response():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_id = data["userId"]
        access_token_payload = data.get("accessTokenPayload", {})
        session_data_in_database = data.get("sessionDataInDatabase", {})
        disable_anti_csrf = data.get("disableAntiCsrf")
        user_context = data.get("userContext", {})

        session_container = session.create_new_session_without_request_response(
            tenant_id,
            user_id,
            access_token_payload,
            session_data_in_database,
            disable_anti_csrf,
            user_context,
        )

        return jsonify(
            {
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
            }
        )

    @app.route("/test/session/getsessionwithoutrequestresponse", methods=["POST"])  # type: ignore
    def get_session_without_request_response():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        access_token = data["accessToken"]
        anti_csrf_token = data.get("antiCsrfToken")
        options = data.get("options")
        user_context = data.get("userContext", {})

        try:
            session_container = session.get_session_without_request_response(
                access_token, anti_csrf_token, options, user_context
            )
            return jsonify(session_container)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/test/session/sessionobject/assertclaims", methods=["POST"])  # type: ignore
    def assert_claims():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        session_container = Session(
            recipe_implementation=SessionRecipe.get_instance().recipe_implementation,
            config=SessionRecipe.get_instance().config,
            access_token=data["session"]["accessToken"],
            front_token=data["session"]["frontToken"],
            refresh_token=None,  # We don't have refresh token in the input
            anti_csrf_token=None,  # We don't have anti-csrf token in the input
            session_handle=data["session"]["sessionHandle"],
            user_id=data["session"]["userId"],
            recipe_user_id=data["session"]["recipeUserId"],
            user_data_in_access_token=data["session"]["userDataInAccessToken"],
            req_res_info=None,  # We don't have this information in the input
            access_token_updated=data["session"]["accessTokenUpdated"],
            tenant_id=data["session"]["tenantId"],
        )
        claim_validators = list(map(deserialize_validator, data["claimValidators"]))

        user_context = data.get("userContext", {})

        try:
            async_to_sync_wrapper.sync(
                session_container.assert_claims(claim_validators, user_context)
            )
            return jsonify(
                {
                    "status": "OK",
                    "updatedSession": {
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
                    },
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

        session_container = Session(
            recipe_implementation=SessionRecipe.get_instance().recipe_implementation,
            config=SessionRecipe.get_instance().config,
            access_token=data["session"]["accessToken"],
            front_token=data["session"]["frontToken"],
            refresh_token=None,  # We don't have refresh token in the input
            anti_csrf_token=None,  # We don't have anti-csrf token in the input
            session_handle=data["session"]["sessionHandle"],
            user_id=data["session"]["userId"],
            recipe_user_id=data["session"]["recipeUserId"],
            user_data_in_access_token=data["session"]["userDataInAccessToken"],
            req_res_info=None,  # We don't have this information in the input
            access_token_updated=data["session"]["accessTokenUpdated"],
            tenant_id=data["session"]["tenantId"],
        )
        access_token_payload_update = data["accessTokenPayloadUpdate"]
        user_context = data.get("userContext", {})

        async_to_sync_wrapper.sync(
            session_container.merge_into_access_token_payload(
                access_token_payload_update, user_context
            )
        )

        return jsonify(
            {
                "status": "OK",
                "updatedSession": {
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
                },
            }
        )
