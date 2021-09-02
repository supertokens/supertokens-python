from supertokens_python.async_to_sync_wrapper import sync


def create_email_verification_token(user_id: str):
    from supertokens_python.thirdpartyemailpassword import create_email_verification_token
    return sync(create_email_verification_token(user_id))


def verify_email_using_token(token: str):
    from supertokens_python.thirdpartyemailpassword import verify_email_using_token
    return sync(verify_email_using_token(token))


def is_email_verified(user_id: str):
    from supertokens_python.thirdpartyemailpassword import is_email_verified
    return sync(is_email_verified(user_id))


def get_users_oldest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.thirdpartyemailpassword import get_users_oldest_first
    return sync(get_users_oldest_first(limit, next_pagination))


def get_users_newest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.thirdpartyemailpassword import get_users_newest_first
    return sync(get_users_newest_first(limit, next_pagination))


def get_user_count():
    from supertokens_python.thirdpartyemailpassword import get_user_count
    return sync(get_user_count())


def get_user_by_id(user_id: str):
    from supertokens_python.thirdpartyemailpassword import get_user_by_id
    return sync(get_user_by_id(user_id))


def get_user_by_third_party_info(third_party_id: str, third_party_user_id: str):
    from supertokens_python.thirdpartyemailpassword import get_user_by_third_party_info
    return sync(get_user_by_third_party_info(third_party_id, third_party_user_id))


def sign_in_up(third_party_id: str, third_party_user_id: str, email: str, email_verified: bool):
    from supertokens_python.thirdpartyemailpassword import sign_in_up
    return sync(sign_in_up(third_party_id, third_party_user_id, email, email_verified))


def create_reset_password_token(user_id: str):
    from supertokens_python.thirdpartyemailpassword import create_reset_password_token
    return sync(create_reset_password_token(user_id))


def reset_password_using_token(token: str, new_password: str):
    from supertokens_python.thirdpartyemailpassword import reset_password_using_token
    return sync(reset_password_using_token(token, new_password))


def sign_in(email: str, password: str):
    from supertokens_python.thirdpartyemailpassword import sign_in
    return sync(sign_in(email, password))


def sign_up(email: str, password: str):
    from supertokens_python.thirdpartyemailpassword import sign_up
    return sync(sign_up(email, password))
