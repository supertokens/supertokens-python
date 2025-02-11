from flask import Flask, jsonify, request
from session import convert_session_to_container  # pylint: disable=import-error
from supertokens_python import convert_to_recipe_user_id
from supertokens_python.recipe.passwordless.interfaces import (
    ConsumeCodeExpiredUserInputCodeError,
    ConsumeCodeIncorrectUserInputCodeError,
    ConsumeCodeOkResult,
    ConsumeCodeRestartFlowError,
    EmailChangeNotAllowedError,
    UpdateUserEmailAlreadyExistsError,
    UpdateUserOkResult,
    UpdateUserPhoneNumberAlreadyExistsError,
    UpdateUserUnknownUserIdError,
)
from supertokens_python.recipe.passwordless.syncio import (
    consume_code,
    create_code,
    signinup,
    update_user,
)

from utils import (  # pylint: disable=import-error
    serialize_recipe_user_id,
    serialize_user,
)  # pylint: disable=import-error


def add_passwordless_routes(app: Flask):
    @app.route("/test/passwordless/signinup", methods=["POST"])  # type: ignore
    def sign_in_up_api():  # type: ignore
        assert request.json is not None
        body = request.json
        session = None
        if "session" in body:
            session = convert_session_to_container(body)

        response = signinup(
            email=body.get("email", None),
            phone_number=body.get("phoneNumber", None),
            tenant_id=body.get("tenantId", "public"),
            user_context=body.get("userContext"),
            session=session,
        )
        return jsonify(
            {
                "status": "OK",
                "createdNewRecipeUser": response.created_new_recipe_user,
                "consumedDevice": response.consumed_device.to_json(),
                **serialize_user(response.user, request.headers.get("fdi-version", "")),
                **serialize_recipe_user_id(
                    response.recipe_user_id, request.headers.get("fdi-version", "")
                ),
            }
        )

    @app.route("/test/passwordless/createcode", methods=["POST"])  # type: ignore
    def create_code_api():  # type: ignore
        assert request.json is not None
        body = request.json
        session = None
        if "session" in body:
            session = convert_session_to_container(body)

        response = create_code(
            email=body.get("email"),
            phone_number=body.get("phoneNumber"),
            tenant_id=body.get("tenantId", "public"),
            user_input_code=body.get("userInputCode"),
            user_context=body.get("userContext"),
            session=session,
        )
        return jsonify(
            {
                "status": "OK",
                "codeId": response.code_id,
                "preAuthSessionId": response.pre_auth_session_id,
                "codeLifeTime": response.code_life_time,
                "deviceId": response.device_id,
                "linkCode": response.link_code,
                "timeCreated": response.time_created,
                "userInputCode": response.user_input_code,
            }
        )

    @app.route("/test/passwordless/consumecode", methods=["POST"])  # type: ignore
    def consume_code_api():  # type: ignore
        assert request.json is not None
        body = request.json
        session = None
        if "session" in body:
            session = convert_session_to_container(body)

        response = consume_code(
            device_id=body.get("deviceId"),
            pre_auth_session_id=body.get("preAuthSessionId"),
            user_input_code=body.get("userInputCode"),
            link_code=body.get("linkCode", None),
            tenant_id=body.get("tenantId", "public"),
            user_context=body.get("userContext"),
            session=session,
        )

        if isinstance(response, ConsumeCodeOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "createdNewRecipeUser": response.created_new_recipe_user,
                    "consumedDevice": response.consumed_device.to_json(),
                    **serialize_user(
                        response.user, request.headers.get("fdi-version", "")
                    ),
                    **serialize_recipe_user_id(
                        response.recipe_user_id, request.headers.get("fdi-version", "")
                    ),
                }
            )
        elif isinstance(response, ConsumeCodeIncorrectUserInputCodeError):
            return jsonify(
                {
                    "status": "INCORRECT_USER_INPUT_CODE_ERROR",
                    "failedCodeInputAttemptCount": response.failed_code_input_attempt_count,
                    "maximumCodeInputAttempts": response.maximum_code_input_attempts,
                }
            )
        elif isinstance(response, ConsumeCodeExpiredUserInputCodeError):
            return jsonify(
                {
                    "status": "EXPIRED_USER_INPUT_CODE_ERROR",
                    "failedCodeInputAttemptCount": response.failed_code_input_attempt_count,
                    "maximumCodeInputAttempts": response.maximum_code_input_attempts,
                }
            )
        elif isinstance(response, ConsumeCodeRestartFlowError):
            return jsonify({"status": "RESTART_FLOW_ERROR"})
        else:
            return jsonify(
                {
                    "status": response.status,
                    "reason": response.reason,
                }
            )

    @app.route("/test/passwordless/updateuser", methods=["POST"])  # type: ignore
    def update_user_api():  # type: ignore
        assert request.json is not None
        body = request.json
        response = update_user(
            recipe_user_id=convert_to_recipe_user_id(body["recipeUserId"]),
            email=body.get("email"),
            phone_number=body.get("phoneNumber"),
            user_context=body.get("userContext"),
        )

        if isinstance(response, UpdateUserOkResult):
            return jsonify({"status": "OK"})
        elif isinstance(response, UpdateUserUnknownUserIdError):
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})
        elif isinstance(response, UpdateUserEmailAlreadyExistsError):
            return jsonify({"status": "EMAIL_ALREADY_EXISTS_ERROR"})
        elif isinstance(response, UpdateUserPhoneNumberAlreadyExistsError):
            return jsonify({"status": "PHONE_NUMBER_ALREADY_EXISTS_ERROR"})
        elif isinstance(response, EmailChangeNotAllowedError):
            return jsonify(
                {"status": "EMAIL_CHANGE_NOT_ALLOWED_ERROR", "reason": response.reason}
            )
        else:
            return jsonify(
                {
                    "status": "PHONE_NUMBER_CHANGE_NOT_ALLOWED_ERROR",
                    "reason": response.reason,
                }
            )
