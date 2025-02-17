from os import environ

from supertokens_python.env.utils import str_to_bool


def FLAG_tldextract_disable_http():
    """
    Disable HTTP calls from `tldextract`.
    """
    val = environ.get("SUPERTOKENS_TLDEXTRACT_DISABLE_HTTP", "0")

    return str_to_bool(val)
