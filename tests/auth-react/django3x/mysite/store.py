import time
from typing import Any, Dict, List, Optional, TypedDict, Union
from urllib.parse import parse_qs, urlparse

from typing_extensions import Literal


class SaveWebauthnTokenUser(TypedDict):
    email: str
    recover_account_link: str
    token: str


latest_url_with_token = ""
code_store: Dict[str, List[Dict[str, Any]]] = {}
accountlinking_config: Dict[str, Any] = {}
enabled_providers: Optional[List[Any]] = None
enabled_recipes: Optional[List[Any]] = None
mfa_info: Dict[str, Any] = {}
contact_method: Union[None, Literal["PHONE", "EMAIL", "EMAIL_OR_PHONE"]] = None
flow_type: Union[
    None, Literal["USER_INPUT_CODE", "MAGIC_LINK", "USER_INPUT_CODE_AND_MAGIC_LINK"]
] = None
webauthn_store: Dict[str, SaveWebauthnTokenUser] = {}


def save_url_with_token(url_with_token: str):
    global latest_url_with_token
    latest_url_with_token = url_with_token


def get_url_with_token() -> str:
    t = 0
    while not latest_url_with_token:
        time.sleep(0.5)
        t += 1
        if t > 10:
            break

    return latest_url_with_token


def save_code(
    pre_auth_session_id: str,
    url_with_link_code: Union[str, None],
    user_input_code: Union[str, None],
):
    global code_store
    codes = code_store.get(pre_auth_session_id, [])
    # replace sub string in url_with_link_code
    if url_with_link_code:
        url_with_link_code = url_with_link_code.replace(
            "?preAuthSessionId", "?test=fix&preAuthSessionId"
        )
    codes.append(
        {"urlWithLinkCode": url_with_link_code, "userInputCode": user_input_code}
    )
    code_store[pre_auth_session_id] = codes


def get_codes(pre_auth_session_id: str) -> List[Dict[str, Any]]:
    return code_store.get(pre_auth_session_id, [])


def save_webauthn_token(user: SaveWebauthnTokenUser, recover_account_link: str):
    global webauthn_store
    webauthn = webauthn_store.get(
        user["email"],
        {"email": user["email"], "recover_account_link": "", "token": ""},
    )
    webauthn["recover_account_link"] = recover_account_link

    # Parse the token from the recoverAccountLink using URL and URLSearchParams
    url = urlparse(recover_account_link)
    token = parse_qs(url.query).get("token")
    if token is not None and len(token) > 0:
        webauthn["token"] = token[0]

    webauthn_store[user["email"]] = webauthn
