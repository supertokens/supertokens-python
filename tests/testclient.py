from fastapi.testclient import TestClient

# The `fastapi.testclient.TestClient` uses a cookie jar to store cookies between requests.
# Our test cases aren't written with this behavior in mind, and for consistency with other SDKs,
# we need a `TestClient` that doesn't retain cookies. The class below inherits from `TestClient`
# and clears the cookie jar before every request.
class TestClientWithNoCookieJar(TestClient):
    def request(self, *args, **kwargs):  # type: ignore
        self.cookies.clear()
        return super().request(*args, **kwargs)  # type: ignore
