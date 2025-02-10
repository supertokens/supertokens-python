import supertokens_python.recipe.multitenancy.syncio as multitenancy
from flask import Flask, jsonify, request
from supertokens_python.recipe.multitenancy.interfaces import (
    AssociateUserToTenantOkResult,
    TenantConfigCreateOrUpdate,
)
from supertokens_python.recipe.thirdparty import (
    ProviderClientConfig,
    ProviderConfig,
    ProviderInput,
)
from supertokens_python.recipe.thirdparty.provider import UserFields, UserInfoMap
from supertokens_python.types import RecipeUserId


def add_multitenancy_routes(app: Flask):
    @app.route("/test/multitenancy/createorupdatetenant", methods=["POST"])  # type: ignore
    def create_or_update_tenant():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        user_context = data.get("userContext")

        config = (
            TenantConfigCreateOrUpdate(
                first_factors=data["config"].get("firstFactors"),
                required_secondary_factors=data["config"].get(
                    "requiredSecondaryFactors"
                ),
                core_config=data["config"].get("coreConfig", {}),
            )
            if "config" in data
            else None
        )

        response = multitenancy.create_or_update_tenant(tenant_id, config, user_context)

        return jsonify({"status": "OK", "createdNew": response.created_new})

    @app.route("/test/multitenancy/deletetenant", methods=["POST"])  # type: ignore
    def delete_tenant():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        user_context = data.get("userContext")

        response = multitenancy.delete_tenant(tenant_id, user_context)

        return jsonify({"status": "OK", "didExist": response.did_exist})

    @app.route("/test/multitenancy/gettenant", methods=["POST"])  # type: ignore
    def get_tenant():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        user_context = data.get("userContext")

        response = multitenancy.get_tenant(tenant_id, user_context)

        if response is None:
            return jsonify({"status": "OK", "tenant": None})

        return jsonify(
            {
                "status": "OK",
                "tenant": {
                    "firstFactors": response.first_factors,
                    "requiredSecondaryFactors": response.required_secondary_factors,
                    "thirdPartyProviders": response.third_party_providers,
                    "coreConfig": response.core_config,
                },
            }
        )

    @app.route("/test/multitenancy/listalltenants", methods=["GET"])  # type: ignore
    def list_all_tenants():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        user_context = data.get("userContext")

        response = multitenancy.list_all_tenants(user_context)

        return jsonify({"status": "OK", "tenants": response.tenants})

    @app.route("/test/multitenancy/createorupdatethirdpartyconfig", methods=["POST"])  # type: ignore
    def create_or_update_third_party_config():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        config = data["config"]
        skip_validation = data.get("skipValidation")
        user_context = data.get("userContext")

        provider_input = ProviderInput(
            config=ProviderConfig(
                third_party_id=config["thirdPartyId"],
                name=config.get("name"),
                clients=[
                    ProviderClientConfig(
                        client_id=c["clientId"],
                        client_secret=c.get("clientSecret"),
                        client_type=c.get("clientType"),
                        scope=c.get("scope"),
                        force_pkce=c.get("forcePKCE", False),
                        additional_config=c.get("additionalConfig"),
                    )
                    for c in config.get("clients", [])
                ],
                authorization_endpoint=config.get("authorizationEndpoint"),
                authorization_endpoint_query_params=config.get(
                    "authorizationEndpointQueryParams"
                ),
                token_endpoint=config.get("tokenEndpoint"),
                token_endpoint_body_params=config.get("tokenEndpointBodyParams"),
                user_info_endpoint=config.get("userInfoEndpoint"),
                user_info_endpoint_query_params=config.get(
                    "userInfoEndpointQueryParams"
                ),
                user_info_endpoint_headers=config.get("userInfoEndpointHeaders"),
                jwks_uri=config.get("jwksURI"),
                oidc_discovery_endpoint=config.get("oidcDiscoveryEndpoint"),
                user_info_map=(
                    UserInfoMap(
                        from_id_token_payload=UserFields(
                            user_id=config.get("userInfoMap", {})
                            .get("fromIdTokenPayload", {})
                            .get("userId"),
                            email=config.get("userInfoMap", {})
                            .get("fromIdTokenPayload", {})
                            .get("email"),
                            email_verified=config.get("userInfoMap", {})
                            .get("fromIdTokenPayload", {})
                            .get("emailVerified"),
                        ),
                        from_user_info_api=UserFields(
                            user_id=config.get("userInfoMap", {})
                            .get("fromUserInfoAPI", {})
                            .get("userId"),
                            email=config.get("userInfoMap", {})
                            .get("fromUserInfoAPI", {})
                            .get("email"),
                            email_verified=config.get("userInfoMap", {})
                            .get("fromUserInfoAPI", {})
                            .get("emailVerified"),
                        ),
                    )
                    if "userInfoMap" in config
                    else None
                ),
                require_email=config.get("requireEmail", True),
            )
        )

        response = multitenancy.create_or_update_third_party_config(
            tenant_id, provider_input.config, skip_validation, user_context
        )

        return jsonify({"status": "OK", "createdNew": response.created_new})

    @app.route("/test/multitenancy/deletethirdpartyconfig", methods=["POST"])  # type: ignore
    def delete_third_party_config():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        third_party_id = data["thirdPartyId"]
        user_context = data.get("userContext")

        response = multitenancy.delete_third_party_config(
            tenant_id, third_party_id, user_context
        )

        return jsonify({"status": "OK", "didExist": response.did_config_exist})

    @app.route("/test/multitenancy/associateusertotenant", methods=["POST"])  # type: ignore
    def associate_user_to_tenant():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        recipe_user_id = RecipeUserId(data["recipeUserId"])
        user_context = data.get("userContext")

        response = multitenancy.associate_user_to_tenant(
            tenant_id, recipe_user_id, user_context
        )

        if isinstance(response, AssociateUserToTenantOkResult):
            return jsonify(
                {
                    "status": "OK",
                    "wasAlreadyAssociated": response.was_already_associated,
                }
            )
        else:
            return jsonify({"status": "UNKNOWN_ERROR"})

    @app.route("/test/multitenancy/disassociateuserfromtenant", methods=["POST"])  # type: ignore
    def disassociate_user_from_tenant():  # type: ignore
        data = request.json
        if data is None:
            return jsonify({"status": "MISSING_DATA_ERROR"})
        tenant_id = data["tenantId"]
        user_id = data["userId"]
        user_context = data.get("userContext")

        response = multitenancy.disassociate_user_from_tenant(
            tenant_id, user_id, user_context
        )

        return jsonify({"status": "OK", "wasAssociated": response.was_associated})
