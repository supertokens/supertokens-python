from supertokens_python.async_to_sync_wrapper import sync


def create_email_verification_token(user_id: str, email: str):
    from supertokens_python.emailverification import create_email_verification_token
    return sync(create_email_verification_token(user_id, email))


def verify_email_using_token(token: str):
    from supertokens_python.emailverification import verify_email_using_token
    return sync(verify_email_using_token(token))


def is_email_verified(user_id: str, email: str):
    from supertokens_python.emailverification import is_email_verified
    return sync(is_email_verified(user_id, email))
