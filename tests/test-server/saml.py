from flask import Flask, jsonify, request
from supertokens_python.recipe.saml.syncio import (
    create_login_request,
    create_or_update_client,
    get_user_info,
    list_clients,
    remove_client,
    verify_saml_response,
)
from supertokens_python.recipe.saml.types import (
    CreateLoginRequestOkResult,
    CreateOrUpdateClientOkResult,
    GetUserInfoOkResult,
    VerifySAMLResponseOkResult,
)


def add_saml_routes(app: Flask):
    @app.route("/test/saml/createorupdateclient", methods=["POST"])  # type: ignore
    def saml_create_or_update_client():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_context = data.get("userContext", {})

        response = create_or_update_client(
            tenant_id=tenant_id,
            redirect_uris=data["redirectURIs"],
            default_redirect_uri=data["defaultRedirectURI"],
            metadata_xml=data["metadataXML"],
            client_id=data.get("clientId"),
            client_secret=data.get("clientSecret"),
            allow_idp_initiated_login=data.get("allowIDPInitiatedLogin"),
            enable_request_signing=data.get("enableRequestSigning"),
            user_context=user_context,
        )

        if isinstance(response, CreateOrUpdateClientOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "client": response.client.to_json(),
                }
            )
        return jsonify({"status": response.status})

    @app.route("/test/saml/listclients", methods=["POST"])  # type: ignore
    def saml_list_clients():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_context = data.get("userContext", {})

        response = list_clients(
            tenant_id=tenant_id,
            user_context=user_context,
        )

        return jsonify(
            {
                "status": "OK",
                "clients": [c.to_json() for c in response.clients],
            }
        )

    @app.route("/test/saml/removeclient", methods=["POST"])  # type: ignore
    def saml_remove_client():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        client_id = data["clientId"]
        user_context = data.get("userContext", {})

        response = remove_client(
            tenant_id=tenant_id,
            client_id=client_id,
            user_context=user_context,
        )

        return jsonify(
            {
                "status": "OK",
                "didExist": response.did_exist,
            }
        )

    @app.route("/test/saml/createloginrequest", methods=["POST"])  # type: ignore
    def saml_create_login_request():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_context = data.get("userContext", {})

        response = create_login_request(
            tenant_id=tenant_id,
            client_id=data["clientId"],
            redirect_uri=data["redirectURI"],
            acs_url=data["acsURL"],
            state=data.get("state"),
            user_context=user_context,
        )

        if isinstance(response, CreateLoginRequestOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "redirectURI": response.redirect_uri,
                }
            )
        return jsonify({"status": response.status})

    @app.route("/test/saml/verifysamlresponse", methods=["POST"])  # type: ignore
    def saml_verify_saml_response():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_context = data.get("userContext", {})

        response = verify_saml_response(
            tenant_id=tenant_id,
            saml_response=data["samlResponse"],
            relay_state=data.get("relayState"),
            user_context=user_context,
        )

        if isinstance(response, VerifySAMLResponseOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "redirectURI": response.redirect_uri,
                }
            )
        return jsonify({"status": response.status})

    @app.route("/test/saml/getuserinfo", methods=["POST"])  # type: ignore
    def saml_get_user_info():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})

        tenant_id = data.get("tenantId", "public")
        user_context = data.get("userContext", {})

        response = get_user_info(
            tenant_id=tenant_id,
            access_token=data["accessToken"],
            client_id=data["clientId"],
            user_context=user_context,
        )

        if isinstance(response, GetUserInfoOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "sub": response.sub,
                    "email": response.email,
                    "claims": response.claims,
                }
            )
        return jsonify({"status": response.status})
