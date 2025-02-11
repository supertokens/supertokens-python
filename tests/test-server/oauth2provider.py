import supertokens_python.recipe.oauth2provider.syncio as OAuth2Provider
from flask import Flask, jsonify, request
from supertokens_python.recipe.oauth2provider.interfaces import (
    CreateOAuth2ClientInput,
    OAuth2TokenValidationRequirements,
    UpdateOAuth2ClientInput,
)


def add_oauth2provider_routes(app: Flask):
    @app.route("/test/oauth2provider/getoauth2clients", methods=["POST"])  # type: ignore
    def get_oauth2_clients_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:getOAuth2Clients", request.json)

        data = request.json.get("input", {})
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        response = OAuth2Provider.get_oauth2_clients(
            page_size=data.get("pageSize"),
            pagination_token=data.get("paginationToken"),
            client_name=data.get("clientName"),
            user_context=data.get("userContext"),
        )
        return jsonify(response.to_json())

    @app.route("/test/oauth2provider/createoauth2client", methods=["POST"])  # type: ignore
    def create_oauth2_client_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:createOAuth2Client", request.json)

        response = OAuth2Provider.create_oauth2_client(
            params=CreateOAuth2ClientInput.from_json(request.json.get("input", {})),
            user_context=request.json.get("userContext"),
        )
        return jsonify(response.to_json())

    @app.route("/test/oauth2provider/updateoauth2client", methods=["POST"])  # type: ignore
    def update_oauth2_client_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:updateOAuth2Client", request.json)

        response = OAuth2Provider.update_oauth2_client(
            params=UpdateOAuth2ClientInput.from_json(request.json.get("input", {})),
            user_context=request.json.get("userContext"),
        )
        return jsonify(response.to_json())

    @app.route("/test/oauth2provider/deleteoauth2client", methods=["POST"])  # type: ignore
    def delete_oauth2_client_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:deleteOAuth2Client", request.json)

        data = request.json.get("input", {})

        response = OAuth2Provider.delete_oauth2_client(
            client_id=data.get("clientId"),
            user_context=data.get("userContext"),
        )
        return jsonify(response.to_json())

    @app.route("/test/oauth2provider/validateoauth2accesstoken", methods=["POST"])  # type: ignore
    def validate_oauth2_access_token_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:validateOAuth2AccessToken", request.json)

        response = OAuth2Provider.validate_oauth2_access_token(
            token=request.json["token"],
            requirements=(
                OAuth2TokenValidationRequirements.from_json(
                    request.json["requirements"]
                )
                if "requirements" in request.json
                else None
            ),
            check_database=request.json.get("checkDatabase"),
            user_context=request.json.get("userContext"),
        )
        return jsonify({"payload": response.payload, "status": "OK"})

    @app.route("/test/oauth2provider/validateoauth2refreshtoken", methods=["POST"])  # type: ignore
    def validate_oauth2_refresh_token_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:validateOAuth2RefreshToken", request.json)

        response = OAuth2Provider.validate_oauth2_refresh_token(
            token=request.json["token"],
            scopes=request.json["scopes"],
            user_context=request.json.get("userContext"),
        )
        return jsonify(response.to_json())

    @app.route("/test/oauth2provider/createtokenforclientcredentials", methods=["POST"])  # type: ignore
    def create_token_for_client_credentials_api():  # type: ignore
        assert request.json is not None
        print("OAuth2Provider:createTokenForClientCredentials", request.json)

        response = OAuth2Provider.create_token_for_client_credentials(
            client_id=request.json["clientId"],
            client_secret=request.json["clientSecret"],
            scope=request.json["scope"],
            audience=request.json["audience"],
            user_context=request.json.get("userContext"),
        )
        return jsonify(response.to_json())
