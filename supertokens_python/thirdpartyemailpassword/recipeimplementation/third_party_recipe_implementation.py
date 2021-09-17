from typing import Union, List

from supertokens_python.thirdparty.interfaces import RecipeInterface, SignInUpResult
from supertokens_python.thirdpartyemailpassword.types import UsersResponse, User
from supertokens_python.thirdpartyemailpassword.interfaces import \
    RecipeInterface as ThirdPartyEmailPasswordRecipeInterface


class RecipeImplementation(RecipeInterface):

    def __init__(self, recipe_implementation: ThirdPartyEmailPasswordRecipeInterface):
        super().__init__()
        self.recipe_implementation = recipe_implementation

    async def get_user_by_id(self, user_id: str) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_id(user_id)
        if user is None or user.third_party_info is None:
            return None

    async def get_users_by_email(self, email: str) -> List[User]:
        users = await self.recipe_implementation.get_users_by_email(email)
        users_result = []

        for user in users:
            if user.third_party_info is not None:
                users_result.append(user)

        return users_result

    async def get_user_by_thirdparty_info(self, third_party_id: str, third_party_user_id: str) -> Union[User, None]:
        user = await self.recipe_implementation.get_user_by_thirdparty_info(third_party_id, third_party_user_id)
        if user is None or user.third_party_info is None:
            return None

        return user

    async def sign_in_up(self, third_party_id: str, third_party_user_id: str, email: str,
                         email_verified: bool) -> SignInUpResult:
        result = await self.recipe_implementation.sign_in_up(third_party_id, third_party_user_id, email, email_verified)

        if result.status == "FIELD_ERROR":
            return result
        if result.user.third_party_info is None:
            raise Exception("Should never come here")

        return SignInUpResult(status="OK", created_new_user=result.created_new_user, user=result.user)

    async def get_users_oldest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never come here")

    async def get_users_newest_first(self, limit: int = None, next_pagination: str = None) -> UsersResponse:
        raise Exception("Should never come here")

    async def get_user_count(self) -> int:
        raise Exception("Should never come here")
