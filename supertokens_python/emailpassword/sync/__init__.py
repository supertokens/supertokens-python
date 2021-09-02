from supertokens_python.async_to_sync_wrapper import sync


def asynccreate_email_verification_token(user_id: str):
    from supertokens_python.emailpassword import create_email_verification_token
    return sync(create_email_verification_token(user_id))


def verify_email_using_token(token: str):
    from supertokens_python.emailpassword import verify_email_using_token
    return sync(verify_email_using_token(token))


def is_email_verified(user_id: str):
    from supertokens_python.emailpassword import is_email_verified
    return sync(is_email_verified(user_id))


def get_users_oldest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.emailpassword import get_users_oldest_first
    return sync(get_users_oldest_first(limit, next_pagination))


def get_users_newest_first(limit: int = None, next_pagination: str = None):
    from supertokens_python.emailpassword import get_users_newest_first
    return sync(get_users_newest_first(limit, next_pagination))


def get_user_count():
    from supertokens_python.emailpassword import get_user_count
    return sync(get_user_count())


def get_user_by_id(user_id: str):
    from supertokens_python.emailpassword import get_user_by_id
    return sync(get_user_by_id(user_id))


def get_user_by_email(email: str):
    from supertokens_python.emailpassword import get_user_by_email
    return sync(get_user_by_email(email))


def create_reset_password_token(user_id: str):
    from supertokens_python.emailpassword import create_reset_password_token
    return sync(create_reset_password_token(user_id))


def reset_password_using_token(token: str, new_password: str):
    from supertokens_python.emailpassword import reset_password_using_token
    return sync(reset_password_using_token(token, new_password))


def sign_in(email: str, password: str):
    from supertokens_python.emailpassword import sign_in
    return sync(sign_in(email, password))


async def sign_up(email: str, password: str):
    from supertokens_python.emailpassword import sign_up
    return sync(sign_up(email, password))
