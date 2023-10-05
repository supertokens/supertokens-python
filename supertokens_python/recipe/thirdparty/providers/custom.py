from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

from httpx import AsyncClient

from jwt import decode  # type: ignore
from jwt.algorithms import RSAAlgorithm
import pkce

from supertokens_python.recipe.thirdparty.exceptions import ClientTypeNotFoundError
from supertokens_python.recipe.thirdparty.providers.utils import (
    DEV_OAUTH_AUTHORIZATION_URL,
    DEV_OAUTH_REDIRECT_URL,
    do_get_request,
    do_post_request,
    get_actual_client_id_from_development_client_id,
    is_using_oauth_development_client_id,
    DEV_KEY_IDENTIFIER,
    DEV_OAUTH_CLIENT_IDS,
)

from ..types import RawUserInfoFromProvider, UserInfo, UserInfoEmail
from ..provider import (
    AuthorisationRedirect,
    Provider,
    ProviderClientConfig,
    ProviderConfig,
    ProviderConfigForClient,
    ProviderInput,
    RedirectUriInfo,
    UserFields,
    UserInfoMap,
)


def get_provider_config_for_client(
    config: ProviderConfig, client_config: ProviderClientConfig
) -> ProviderConfigForClient:
    return ProviderConfigForClient(
        # ProviderClientConfig
        client_id=client_config.client_id,
        client_secret=client_config.client_secret,
        client_type=client_config.client_type,
        scope=client_config.scope,
        force_pkce=client_config.force_pkce,
        additional_config=client_config.additional_config,
        # CommonProviderConfig
        third_party_id=config.third_party_id,
        name=config.name,
        authorization_endpoint=config.authorization_endpoint,
        authorization_endpoint_query_params=config.authorization_endpoint_query_params,
        token_endpoint=config.token_endpoint,
        token_endpoint_body_params=config.token_endpoint_body_params,
        user_info_endpoint=config.user_info_endpoint,
        user_info_endpoint_query_params=config.user_info_endpoint_query_params,
        user_info_endpoint_headers=config.user_info_endpoint_headers,
        jwks_uri=config.jwks_uri,
        oidc_discovery_endpoint=config.oidc_discovery_endpoint,
        user_info_map=config.user_info_map,
        require_email=config.require_email,
        validate_id_token_payload=config.validate_id_token_payload,
        generate_fake_email=config.generate_fake_email,
        validate_access_token=config.validate_access_token,
    )


def access_field(obj: Any, key: str) -> Any:
    key_parts = key.split(".")
    for part in key_parts:
        if isinstance(obj, dict):
            obj = obj.get(part)  # type: ignore
        else:
            return None

    return obj


def get_supertokens_user_info_result_from_raw_user_info(
    config: ProviderConfigForClient,
    raw_user_info_from_provider: RawUserInfoFromProvider,
) -> UserInfo:
    third_party_user_id = ""

    if config.user_info_map is None:
        raise Exception("user info map is missing")

    if config.user_info_map.from_user_info_api is None:
        config.user_info_map.from_user_info_api = UserFields()
    if config.user_info_map.from_id_token_payload is None:
        config.user_info_map.from_id_token_payload = UserFields()

    if config.user_info_map.from_user_info_api.user_id is not None:
        user_id = access_field(
            raw_user_info_from_provider.from_user_info_api,
            config.user_info_map.from_user_info_api.user_id,
        )
        if user_id is not None:
            third_party_user_id = str(user_id)

    if config.user_info_map.from_id_token_payload.user_id is not None:
        user_id = access_field(
            raw_user_info_from_provider.from_id_token_payload,
            config.user_info_map.from_id_token_payload.user_id,
        )
        if user_id is not None:
            third_party_user_id = str(user_id)

    if third_party_user_id == "":
        raise Exception("third party user id is missing")

    result = UserInfo(
        third_party_user_id=third_party_user_id,
    )

    email = ""

    if config.user_info_map.from_user_info_api.email is not None:
        email_val = access_field(
            raw_user_info_from_provider.from_user_info_api,
            config.user_info_map.from_user_info_api.email,
        )
        if email_val is not None:
            email = email_val

    if config.user_info_map.from_id_token_payload.email is not None:
        email_val = access_field(
            raw_user_info_from_provider.from_id_token_payload,
            config.user_info_map.from_id_token_payload.email,
        )
        if email_val is not None:
            email = email_val

    if email != "":
        result.email = UserInfoEmail(email, False)

        if config.user_info_map.from_user_info_api.email_verified is not None:
            email_verified = access_field(
                raw_user_info_from_provider.from_user_info_api,
                config.user_info_map.from_user_info_api.email_verified,
            )
            if email_verified is not None:
                result.email.is_verified = str(email_verified).lower() == "true"

        if config.user_info_map.from_id_token_payload.email_verified is not None:
            email_verified = access_field(
                raw_user_info_from_provider.from_id_token_payload,
                config.user_info_map.from_id_token_payload.email_verified,
            )
            if email_verified is not None:
                result.email.is_verified = str(email_verified).lower() == "true"

    return result


async def verify_id_token_from_jwks_endpoint_and_get_payload(
    id_token: str, jwks_uri: str, audience: str
):
    public_keys: List[RSAAlgorithm] = []
    async with AsyncClient() as client:
        response = await client.get(jwks_uri)  # type:ignore
        key_payload = response.json()
        for key in key_payload["keys"]:
            public_keys.append(RSAAlgorithm.from_jwk(key))  # type: ignore

    err = Exception("id token verification failed")
    for key in public_keys:
        try:
            return decode(jwt=id_token, key=key, audience=[audience], algorithms=["RS256"])  # type: ignore
        except Exception as e:
            err = e
    raise err


def merge_into_dict(src: Dict[str, Any], dest: Dict[str, Any]) -> Dict[str, Any]:
    res = dest.copy()
    for k, v in src.items():
        if v is None:
            if k in res:
                del res[k]
        else:
            res[k] = v

    return res


def is_using_development_client_id(client_id: str) -> bool:
    return client_id.startswith(DEV_KEY_IDENTIFIER) or client_id in DEV_OAUTH_CLIENT_IDS


class GenericProvider(Provider):
    def __init__(self, provider_config: ProviderConfig):
        self.input_config = input_config = self._normalize_input(provider_config)

        provider_config_for_client = ProviderConfigForClient(
            # Will automatically get replaced with correct value
            # in get_provider_config_for_client
            # when fetch_and_set_config function runs
            client_id="temp",
            client_secret=None,
            client_type=None,
            scope=None,
            force_pkce=False,
            additional_config=None,
            name=input_config.name,
            authorization_endpoint=input_config.authorization_endpoint,
            authorization_endpoint_query_params=input_config.authorization_endpoint_query_params,
            token_endpoint=input_config.token_endpoint,
            token_endpoint_body_params=input_config.token_endpoint_body_params,
            user_info_endpoint=input_config.user_info_endpoint,
            user_info_endpoint_query_params=input_config.user_info_endpoint_query_params,
            user_info_endpoint_headers=input_config.user_info_endpoint_headers,
            jwks_uri=input_config.jwks_uri,
            oidc_discovery_endpoint=input_config.oidc_discovery_endpoint,
            user_info_map=input_config.user_info_map,
            require_email=input_config.require_email,
            validate_id_token_payload=input_config.validate_id_token_payload,
            generate_fake_email=input_config.generate_fake_email,
        )
        super().__init__(input_config.third_party_id, provider_config_for_client)

    def _normalize_input(  # pylint: disable=no-self-use
        self, input_config: ProviderConfig
    ) -> ProviderConfig:
        if input_config.user_info_map is None:
            input_config.user_info_map = UserInfoMap(
                from_id_token_payload=UserFields(),
                from_user_info_api=UserFields(),
            )
        if input_config.user_info_map.from_user_info_api is None:
            input_config.user_info_map.from_user_info_api = UserFields()
        if input_config.user_info_map.from_id_token_payload is None:
            input_config.user_info_map.from_id_token_payload = UserFields()

        # These are safe defaults common to most providers. Each provider
        # implementations override these as necessary
        if input_config.user_info_map.from_id_token_payload.user_id is None:
            input_config.user_info_map.from_id_token_payload.user_id = "sub"

        if input_config.user_info_map.from_id_token_payload.email is None:
            input_config.user_info_map.from_id_token_payload.email = "email"

        if input_config.user_info_map.from_id_token_payload.email_verified is None:
            input_config.user_info_map.from_id_token_payload.email_verified = (
                "email_verified"
            )

        if input_config.user_info_map.from_user_info_api.user_id is None:
            input_config.user_info_map.from_user_info_api.user_id = "sub"

        if input_config.user_info_map.from_user_info_api.email is None:
            input_config.user_info_map.from_user_info_api.email = "email"

        if input_config.user_info_map.from_user_info_api.email_verified is None:
            input_config.user_info_map.from_user_info_api.email_verified = (
                "email_verified"
            )

        if input_config.generate_fake_email is None:

            async def default_generate_fake_email(
                _tenant_id: str, third_party_user_id: str, _: Dict[str, Any]
            ) -> str:
                return (
                    f"{third_party_user_id}@{input_config.third_party_id}.fakeemail.com"
                )

            input_config.generate_fake_email = default_generate_fake_email

        return input_config

    async def get_config_for_client_type(
        self, client_type: Optional[str], user_context: Dict[str, Any]
    ) -> ProviderConfigForClient:
        if client_type is None:
            if self.input_config.clients is None or len(self.input_config.clients) != 1:
                raise ClientTypeNotFoundError(
                    "please provide exactly one client config or pass clientType or tenantId"
                )

            return get_provider_config_for_client(
                self.input_config, self.input_config.clients[0]
            )

        if self.input_config.clients is not None:
            for client in self.input_config.clients:
                if client.client_type == client_type:
                    return get_provider_config_for_client(self.input_config, client)

        raise ClientTypeNotFoundError(
            f"Could not find client config for clientType: {client_type}"
        )

    async def get_authorisation_redirect_url(
        self,
        redirect_uri_on_provider_dashboard: str,
        user_context: Dict[str, Any],
    ) -> AuthorisationRedirect:
        query_params: Dict[str, str] = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri_on_provider_dashboard,
            "response_type": "code",
        }

        if self.config.scope is not None:
            query_params["scope"] = " ".join(self.config.scope)

        pkce_code_verifier: Union[str, None] = None

        if self.config.client_secret is None or self.config.force_pkce:
            code_verifier, code_challenge = pkce.generate_pkce_pair(64)
            query_params["code_challenge"] = code_challenge
            query_params["code_challenge_method"] = "S256"
            pkce_code_verifier = code_verifier

        if self.config.authorization_endpoint_query_params is not None:
            for k, v in self.config.authorization_endpoint_query_params.items():
                if v is None:
                    del query_params[k]
                else:
                    query_params[k] = v

        if self.config.authorization_endpoint is None:
            raise Exception(
                "ThirdParty provider's authorizationEndpoint is not configured."
            )

        url: str = self.config.authorization_endpoint

        # Transformation needed for dev keys BEGIN
        if is_using_oauth_development_client_id(self.config.client_id):
            query_params["client_id"] = get_actual_client_id_from_development_client_id(
                self.config.client_id
            )
            query_params["actual_redirect_uri"] = url
            url = DEV_OAUTH_AUTHORIZATION_URL
        # Transformation needed for dev keys END

        url_obj = urlparse(url)
        qparams = parse_qs(url_obj.query)
        for k, v in query_params.items():
            qparams[k] = [v]

        url = url_obj._replace(query=urlencode(qparams, doseq=True)).geturl()

        return AuthorisationRedirect(url, pkce_code_verifier)

    async def exchange_auth_code_for_oauth_tokens(
        self, redirect_uri_info: RedirectUriInfo, user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        if self.config.token_endpoint is None:
            raise Exception("ThirdParty provider's tokenEndpoint is not configured.")

        token_api_url = self.config.token_endpoint
        access_token_params: Dict[str, str] = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri_info.redirect_uri_on_provider_dashboard,
            "code": redirect_uri_info.redirect_uri_query_params["code"],
            "grant_type": "authorization_code",
        }
        if self.config.client_secret is not None:
            access_token_params["client_secret"] = self.config.client_secret

        if redirect_uri_info.pkce_code_verifier is not None:
            access_token_params["code_verifier"] = redirect_uri_info.pkce_code_verifier

        if self.config.token_endpoint_body_params is not None:
            access_token_params = merge_into_dict(
                self.config.token_endpoint_body_params, access_token_params
            )

        # Transformation needed for dev keys BEGIN
        if is_using_oauth_development_client_id(self.config.client_id):
            access_token_params[
                "client_id"
            ] = get_actual_client_id_from_development_client_id(self.config.client_id)
            access_token_params["redirect_uri"] = DEV_OAUTH_REDIRECT_URL
        # Transformation needed for dev keys END

        _, body = await do_post_request(token_api_url, access_token_params)
        return body

    async def get_user_info(
        self, oauth_tokens: Dict[str, Any], user_context: Dict[str, Any]
    ) -> UserInfo:
        access_token: Union[str, None] = oauth_tokens.get("access_token")
        id_token: Union[str, None] = oauth_tokens.get("id_token")

        raw_user_info_from_provider = RawUserInfoFromProvider({}, {})
        if id_token is not None and self.config.jwks_uri is not None:
            raw_user_info_from_provider.from_id_token_payload = (
                await verify_id_token_from_jwks_endpoint_and_get_payload(
                    id_token,
                    self.config.jwks_uri,
                    get_actual_client_id_from_development_client_id(
                        self.config.client_id
                    ),
                )
            )

            if self.config.validate_id_token_payload is not None:
                await self.config.validate_id_token_payload(
                    raw_user_info_from_provider.from_id_token_payload,
                    self.config,
                    user_context,
                )

        if self.config.validate_access_token is not None and access_token is not None:
            await self.config.validate_access_token(
                access_token, self.config, user_context
            )

        if access_token is not None and self.config.user_info_endpoint is not None:
            headers: Dict[str, str] = {"Authorization": f"Bearer {access_token}"}
            query_params: Dict[str, str] = {}

            if self.config.user_info_endpoint_headers is not None:
                headers = merge_into_dict(
                    self.config.user_info_endpoint_headers, headers
                )

            if self.config.user_info_endpoint_query_params is not None:
                query_params = merge_into_dict(
                    self.config.user_info_endpoint_query_params, query_params
                )

            raw_user_info_from_provider.from_user_info_api = await do_get_request(
                self.config.user_info_endpoint, query_params, headers
            )

        user_info_result = get_supertokens_user_info_result_from_raw_user_info(
            self.config, raw_user_info_from_provider
        )

        return UserInfo(
            third_party_user_id=user_info_result.third_party_user_id,
            email=user_info_result.email,
            raw_user_info_from_provider=raw_user_info_from_provider,
        )


def NewProvider(
    input: ProviderInput,  # pylint: disable=redefined-builtin
    base_class: Callable[[ProviderConfig], Provider] = GenericProvider,
) -> Provider:
    provider_instance = base_class(input.config)
    if input.override is not None:
        provider_instance = input.override(provider_instance)

    return provider_instance
