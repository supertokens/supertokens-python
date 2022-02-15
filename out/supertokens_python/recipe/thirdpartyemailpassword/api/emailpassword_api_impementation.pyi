from supertokens_python.recipe.emailpassword.interfaces import APIInterface as APIInterface
from supertokens_python.recipe.thirdpartyemailpassword.interfaces import APIInterface as ThirdPartyEmailPasswordAPIInterface

def get_interface_impl(api_implementation: ThirdPartyEmailPasswordAPIInterface) -> APIInterface: ...
