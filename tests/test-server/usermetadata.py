from flask import Flask, jsonify, request
from supertokens_python.recipe.usermetadata.syncio import (
    clear_user_metadata,
    get_user_metadata,
    update_user_metadata,
)


def add_usermetadata_routes(app: Flask):
    @app.route("/test/usermetadata/getusermetadata", methods=["POST"])  # type: ignore
    def get_user_metadata_api():  # type: ignore
        assert request.json is not None
        user_id = request.json["userId"]
        response = get_user_metadata(
            user_id=user_id, user_context=request.json.get("userContext")
        )
        return jsonify({"metadata": response.metadata})

    @app.route("/test/usermetadata/updateusermetadata", methods=["POST"])  # type: ignore
    def update_user_metadata_api():  # type: ignore
        assert request.json is not None
        user_id = request.json["userId"]
        metadata_update = request.json["metadataUpdate"]

        response = update_user_metadata(
            user_id=user_id,
            metadata_update=metadata_update,
            user_context=request.json.get("userContext"),
        )
        return jsonify({"metadata": response.metadata})

    @app.route("/test/usermetadata/clearusermetadata", methods=["POST"])  # type: ignore
    def clear_user_metadata_api():  # type: ignore
        assert request.json is not None
        user_id = request.json["userId"]
        clear_user_metadata(
            user_id=user_id, user_context=request.json.get("userContext")
        )
        return jsonify({"status": "OK"})
