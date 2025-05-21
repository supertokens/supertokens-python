from typing import cast

from flask import Flask, jsonify, request
from pydantic.alias_generators import to_snake
from session import convert_session_to_container
from supertokens_python.recipe.webauthn import (
    consume_recover_account_token,
    create_recover_account_link,
    generate_recover_account_token,
    get_credential,
    get_generated_options,
    get_user_from_recover_account_token,
    list_credentials,
    recover_account,
    register_credential,
    register_options,
    remove_credential,
    remove_generated_options,
    send_email,
    send_recover_account_email,
    sign_in,
    sign_in_options,
    sign_up,
    verify_credentials,
)
from supertokens_python.recipe.webauthn.interfaces.api import (
    TypeWebauthnRecoverAccountEmailDeliveryInput,
    WebauthnRecoverAccountEmailDeliveryUser,
)
from supertokens_python.recipe.webauthn.interfaces.recipe import (
    AuthenticationPayload,
    AuthenticatorAssertionResponseJSON,
    AuthenticatorAttestationResponseJSON,
    RegistrationPayload,
)
from supertokens_python.types.response import StatusResponseBaseModel


def add_webauthn_routes(app: Flask):
    @app.route("/test/webauthn/registeroptions", methods=["POST"])
    def webauthn_register_options():  # type: ignore
        assert request.json is not None
        response = register_options.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/signinoptions", methods=["POST"])
    def webauthn_sign_in_options():  # type: ignore
        assert request.json is not None
        response = sign_in_options.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/getgeneratedoptions", methods=["POST"])
    def webauthn_get_generated_options():  # type: ignore
        assert request.json is not None
        response = get_generated_options.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/signup", methods=["POST"])
    def webauthn_signup():  # type: ignore
        assert request.json is not None
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request.json)

        response = sign_up.sync(
            **{
                **{to_snake(k): v for k, v in request.json.items()},
                # Create model without validation so that we can test edge cases
                "credential": RegistrationPayload.model_construct(
                    **{
                        k: v
                        for k, v in request.json["credential"].items()
                        if k != "response"
                    },
                    response=AuthenticatorAttestationResponseJSON.model_construct(
                        **request.json["credential"]["response"],
                    ),
                ),
                "session": session,
            }  # type: ignore
        )

        return jsonify(response.to_json())

    @app.route("/test/webauthn/signin", methods=["POST"])
    def webauthn_signin():  # type: ignore
        assert request.json is not None
        session = None
        if "session" in request.json:
            session = convert_session_to_container(request.json)
        response = sign_in.sync(
            **{
                **{to_snake(k): v for k, v in request.json.items()},
                # Create model without validation so that we can test edge cases
                "credential": AuthenticationPayload.model_construct(
                    **{
                        k: v
                        for k, v in request.json["credential"].items()
                        if k != "response"
                    },
                    response=AuthenticatorAssertionResponseJSON.model_construct(
                        **request.json["credential"]["response"],
                    ),
                ),
                "session": session,
            }  # type: ignore
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/verifycredentials", methods=["POST"])
    def webauthn_verify_credentials():  # type: ignore
        assert request.json is not None
        response = cast(
            StatusResponseBaseModel[str],
            verify_credentials.sync(
                {
                    **{to_snake(k): v for k, v in request.json.items()},
                    # Create model without validation so that we can test edge cases
                    "credential": AuthenticationPayload.model_construct(
                        **{
                            k: v
                            for k, v in request.json["credential"].items()
                            if k != "response"
                        },
                        response=AuthenticatorAssertionResponseJSON.model_construct(
                            **request.json["credential"]["response"],
                        ),
                    ),
                }  # type: ignore
            ),
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/generaterecoveraccounttoken", methods=["POST"])
    def webauthn_generate_recover_account_token():  # type: ignore
        assert request.json is not None
        response = generate_recover_account_token.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/recoveraccount", methods=["POST"])
    def webauthn_recover_account():  # type: ignore
        assert request.json is not None
        response = recover_account.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/consumerecoveraccounttoken", methods=["POST"])
    def webauthn_consume_recover_account_token():  # type: ignore
        assert request.json is not None
        response = consume_recover_account_token.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/registercredential", methods=["POST"])
    def webauthn_register_credential():  # type: ignore
        assert request.json is not None
        response = register_credential.sync(
            **{
                **{to_snake(k): v for k, v in request.json.items()},
                # Create model without validation so that we can test edge cases
                "credential": RegistrationPayload.model_construct(
                    **{
                        k: v
                        for k, v in request.json["credential"].items()
                        if k != "response"
                    },
                    response=AuthenticatorAttestationResponseJSON.model_construct(
                        **request.json["credential"]["response"],
                    ),
                ),
            }  # type: ignore
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/createrecoveraccountlink", methods=["POST"])
    def webauthn_create_recover_account_link():  # type: ignore
        assert request.json is not None
        response = create_recover_account_link.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/sendrecoveraccountemail", methods=["POST"])
    def webauthn_send_recover_account_email():  # type: ignore
        assert request.json is not None
        response = send_recover_account_email.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/sendemail", methods=["POST"])
    def webauthn_send_email():  # type: ignore
        assert request.json is not None
        response = send_email.sync(
            template_vars=TypeWebauthnRecoverAccountEmailDeliveryInput(
                user=WebauthnRecoverAccountEmailDeliveryUser(
                    id=request.json["user"]["id"],
                    recipe_user_id=request.json["user"]["recipeUserId"],
                    email=request.json["user"]["email"],
                ),
                recover_account_link=request.json["recoverAccountLink"],
                tenant_id=request.json["tenantId"],
            ),
            user_context=request.json.get("userContext"),
        )
        return jsonify(response)

    @app.route("/test/webauthn/getuserfromrecoveraccounttoken", methods=["POST"])
    def webauthn_get_user_from_recover_account_token():  # type: ignore
        assert request.json is not None
        response = get_user_from_recover_account_token.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/removegeneratedoptions", methods=["POST"])
    def webauthn_remove_generated_options():  # type: ignore
        assert request.json is not None
        response = remove_generated_options.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/removecredential", methods=["POST"])
    def webauthn_remove_credential():  # type: ignore
        assert request.json is not None
        response = remove_credential.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/getcredential", methods=["POST"])
    def webauthn_get_credential():  # type: ignore
        assert request.json is not None
        response = get_credential.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())

    @app.route("/test/webauthn/listcredentials", methods=["POST"])
    def webauthn_list_credentials():  # type: ignore
        assert request.json is not None
        response = list_credentials.sync(
            **{to_snake(k): v for k, v in request.json.items()}
        )
        return jsonify(response.to_json())
