from supertokens_python.exceptions import SuperTokensError


class SuperTokensDashboardError(SuperTokensError):
    pass


class DashboardOperationNotAllowedError(SuperTokensDashboardError):
    pass
