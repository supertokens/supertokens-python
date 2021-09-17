from supertokens_python.emailpassword.api.implementation import APIImplementation as EmailPasswordImplementation
from supertokens_python.emailpassword.interfaces import APIOptions as EmailPasswordAPIOptions
from supertokens_python.emailpassword.interfaces import PasswordResetPostResponse, \
    GeneratePasswordResetTokenPostResponse, EmailExistsGetResponse
from supertokens_python.thirdparty.api.implementation import APIImplementation as ThirdPartyImplementation
from supertokens_python.thirdparty.interfaces import APIInterface, APIOptions, \
    AuthorisationUrlGetResponse
from supertokens_python.thirdparty.provider import Provider


class APIImplementation(APIInterface):
    def __init__(self):
        super().__init__()
        self.email_password_implementation = EmailPasswordImplementation
        self.third_party_implementation = ThirdPartyImplementation

    async def email_exists_get(self, email: str, options: EmailPasswordAPIOptions) -> EmailExistsGetResponse:
        return await self.email_password_implementation.email_exists_get(email, options)

    async def generate_password_reset_token_post(self, id: str, value: str,
                                                 options: EmailPasswordAPIOptions) -> GeneratePasswordResetTokenPostResponse:
        return await self.email_password_implementation.generate_password_reset_token_post([id, value], options)

    async def password_reset_post(self, id: str, value: str, token,
                                  options: EmailPasswordAPIOptions) -> PasswordResetPostResponse:
        return await self.email_password_implementation.password_reset_post([id, value], token,  options)

    async def sign_in_up_post(self, sign_in_up_input):
        pass

    async def authorisation_url_get(self, provider: Provider, api_options: APIOptions) -> AuthorisationUrlGetResponse:
        return await self.third_party_implementation.authorisation_url_get(provider, api_options)

