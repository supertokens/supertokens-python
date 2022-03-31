
from typing import Any, Dict, Generic, TypeVar, Union

from supertokens_python.ingredients.emaildelivery.types import (
    EmailDeliveryInterface, TypeInput)

_T = TypeVar('_T')


class DefaultImp(EmailDeliveryInterface[_T]):
    def __init__(self, config: TypeInput[_T]) -> None:
        self.config = config

    def override(self, oi: EmailDeliveryInterface[_T]) -> EmailDeliveryInterface[_T]:
        return oi

    async def send_email(self, email_input: Union[_T, Dict[str, Any]]) -> Any:
        await self.config.service.send_email(email_input)


class EmailDeliveryIngredient(Generic[_T]):
    ingredient_interface_impl: EmailDeliveryInterface[_T]

    def __init__(self, config: TypeInput[_T]) -> None:
        oi = DefaultImp[_T](config)

        self.ingredient_interface_impl = oi if (config is None or config.override is None) else config.override(oi)
