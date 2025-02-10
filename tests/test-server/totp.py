from flask import Flask, jsonify, request
from supertokens_python.recipe.totp.syncio import create_device, verify_device
from supertokens_python.recipe.totp.types import (
    CreateDeviceOkResult,
    DeviceAlreadyExistsError,
    InvalidTOTPError,
    UnknownDeviceError,
    VerifyDeviceOkResult,
)


def add_totp_routes(app: Flask):
    @app.route("/test/totp/createdevice", methods=["POST"])  # type: ignore
    def create_device_api():  # type: ignore
        assert request.json is not None
        body = request.json
        response = create_device(
            user_id=body.get("userId"),
            user_identifier_info=body.get("userIdentifierInfo"),
            device_name=body.get("deviceName"),
            skew=body.get("skew"),
            period=body.get("period"),
            user_context=body.get("userContext"),
        )
        if isinstance(response, CreateDeviceOkResult):
            return jsonify(response.to_json())
        elif isinstance(response, DeviceAlreadyExistsError):
            return jsonify(response.to_json())
        else:
            return jsonify({"status": "UNKNOWN_USER_ID_ERROR"})

    @app.route("/test/totp/verifydevice", methods=["POST"])  # type: ignore
    def verify_device_api():  # type: ignore
        assert request.json is not None
        body = request.json
        response = verify_device(
            tenant_id=body.get("tenantId"),
            user_id=body.get("userId"),
            device_name=body.get("deviceName"),
            totp=body.get("totp"),
            user_context=body.get("userContext"),
        )
        if isinstance(response, VerifyDeviceOkResult):
            return jsonify(response.to_json())
        elif isinstance(response, UnknownDeviceError):
            return jsonify(response.to_json())
        elif isinstance(response, InvalidTOTPError):
            return jsonify(response.to_json())
        else:
            return jsonify(response.to_json())
