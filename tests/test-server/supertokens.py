from flask import Flask, jsonify, request
from supertokens_python.recipe.thirdparty.types import ThirdPartyInfo
from supertokens_python.syncio import (
    delete_user,
    get_user,
    get_users_newest_first,
    get_users_oldest_first,
    list_users_by_account_info,
)
from supertokens_python.types.base import AccountInfoInput


def add_supertokens_routes(app: Flask):
    @app.route("/test/supertokens/getuser", methods=["POST"])  # type: ignore
    def get_user_api():  # type: ignore
        assert request.json is not None
        response = get_user(request.json["userId"], request.json.get("userContext"))
        return jsonify(None if response is None else response.to_json())

    @app.route("/test/supertokens/deleteuser", methods=["POST"])  # type: ignore
    def delete_user_api():  # type: ignore
        assert request.json is not None
        delete_user(
            request.json["userId"],
            request.json.get("removeAllLinkedAccounts", True),
            request.json.get("userContext"),
        )
        return jsonify({"status": "OK"})

    @app.route("/test/supertokens/listusersbyaccountinfo", methods=["POST"])  # type: ignore
    def list_users_by_account_info_api():  # type: ignore
        assert request.json is not None
        response = list_users_by_account_info(
            request.json["tenantId"],
            AccountInfoInput(
                email=request.json["accountInfo"].get("email", None),
                phone_number=request.json["accountInfo"].get("phoneNumber", None),
                third_party=(
                    None
                    if "thirdParty" not in request.json["accountInfo"]
                    else ThirdPartyInfo(
                        third_party_id=request.json["accountInfo"]["thirdParty"]["id"],
                        third_party_user_id=request.json["accountInfo"]["thirdParty"][
                            "userId"
                        ],
                    )
                ),
            ),
            request.json.get("doUnionOfAccountInfo", False),
            request.json.get("userContext"),
        )

        return jsonify([r.to_json() for r in response])

    @app.route("/test/supertokens/getusersnewestfirst", methods=["POST"])  # type: ignore
    def get_users_newest_first_api():  # type: ignore
        assert request.json is not None
        response = get_users_newest_first(
            include_recipe_ids=request.json.get("includeRecipeIds"),
            limit=request.json.get("limit"),
            pagination_token=request.json.get("paginationToken"),
            tenant_id=request.json.get("tenantId"),
            user_context=request.json.get("userContext"),
        )
        return jsonify(
            {
                "nextPaginationToken": response.next_pagination_token,
                "users": [r.to_json() for r in response.users],
            }
        )

    @app.route("/test/supertokens/getusersoldestfirst", methods=["POST"])  # type: ignore
    def get_users_oldest_first_api():  # type: ignore
        assert request.json is not None
        response = get_users_oldest_first(
            include_recipe_ids=request.json.get("includeRecipeIds"),
            limit=request.json.get("limit"),
            pagination_token=request.json.get("paginationToken"),
            tenant_id=request.json.get("tenantId"),
            user_context=request.json.get("userContext"),
        )
        return jsonify(
            {
                "nextPaginationToken": response.next_pagination_token,
                "users": [r.to_json() for r in response.users],
            }
        )
