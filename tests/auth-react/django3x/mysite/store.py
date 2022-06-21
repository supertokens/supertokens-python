from typing import Any, Dict, List, Union

_LATEST_URL_WITH_TOKEN = None


def save_url_with_token(url_with_token: str):
    global _LATEST_URL_WITH_TOKEN
    _LATEST_URL_WITH_TOKEN = url_with_token  # type: ignore


def get_url_with_token() -> str:
    return _LATEST_URL_WITH_TOKEN  # type: ignore


_CODE_STORE: Dict[str, List[Dict[str, Any]]] = {}


def save_code(pre_auth_session_id: str, url_with_link_code: Union[str, None], user_input_code: Union[str, None]):
    global _CODE_STORE
    codes = _CODE_STORE.get(pre_auth_session_id, [])
    codes.append({
        'urlWithLinkCode': url_with_link_code,
        'userInputCode': user_input_code
    })
    _CODE_STORE[pre_auth_session_id] = codes


def get_codes(pre_auth_session_id: str) -> List[Dict[str, Any]]:
    return _CODE_STORE.get(pre_auth_session_id, [])
