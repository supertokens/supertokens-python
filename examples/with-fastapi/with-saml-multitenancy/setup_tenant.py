"""
Setup script for SAML + Multitenancy example.

Prerequisites:
  - SuperTokens Core running locally on http://localhost:3567
  - pip install supertokens-python httpx

This script:
  1. Creates a tenant "mocksaml" with thirdparty as a first factor
  2. Fetches SAML metadata from https://mocksaml.com/api/saml/metadata
  3. Creates a SAML client for the tenant using that metadata
  4. Adds the SAML client as a thirdparty provider on the tenant
"""

import asyncio
import base64
import sys
from urllib.request import Request, urlopen

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import multitenancy, saml, session, thirdparty
from supertokens_python.recipe.multitenancy.asyncio import (
    create_or_update_tenant,
    create_or_update_third_party_config,
)
from supertokens_python.recipe.multitenancy.interfaces import TenantConfigCreateOrUpdate
from supertokens_python.recipe.saml.asyncio import create_or_update_client
from supertokens_python.recipe.thirdparty.provider import (
    ProviderClientConfig,
    ProviderConfig,
)

TENANT_ID = "mocksaml"
CORE_URL = "http://localhost:3567"
API_DOMAIN = "http://localhost:3001"
WEBSITE_DOMAIN = "http://localhost:3000"
MOCKSAML_METADATA_URL = "https://mocksaml.com/api/saml/metadata"


async def main():
    # Minimal SDK init — just enough to call recipe functions
    init(
        supertokens_config=SupertokensConfig(connection_uri=CORE_URL),
        app_info=InputAppInfo(
            app_name="SAML Setup",
            api_domain=API_DOMAIN,
            website_domain=WEBSITE_DOMAIN,
        ),
        framework="fastapi",
        recipe_list=[
            session.init(),
            multitenancy.init(),
            saml.init(),
            thirdparty.init(),
        ],
    )

    # ── Step 1: Create tenant ────────────────────────────────────
    print(f"1. Creating tenant '{TENANT_ID}'...")
    tenant_result = await create_or_update_tenant(
        tenant_id=TENANT_ID,
        config=TenantConfigCreateOrUpdate(
            first_factors=["thirdparty"],
        ),
    )
    print(f"   Status: {tenant_result.status}")

    # ── Step 2: Fetch metadata & create SAML client ──────────────
    print(f"2. Fetching SAML metadata from {MOCKSAML_METADATA_URL}...")
    req = Request(MOCKSAML_METADATA_URL, headers={"User-Agent": "supertokens-setup"})
    with urlopen(req) as resp:
        metadata_xml_raw = resp.read().decode("utf-8")

    metadata_xml_b64 = base64.b64encode(metadata_xml_raw.encode("utf-8")).decode(
        "utf-8"
    )

    redirect_uri = f"{WEBSITE_DOMAIN}/auth/callback/saml-{TENANT_ID}"
    print(f"   Creating SAML client (redirect_uri={redirect_uri})...")

    saml_result = await create_or_update_client(
        tenant_id=TENANT_ID,
        redirect_uris=[redirect_uri],
        default_redirect_uri=redirect_uri,
        metadata_xml=metadata_xml_b64,
    )

    if saml_result.status != "OK":
        print(f"   FAILED: {saml_result.status}")
        sys.exit(1)

    client = saml_result.client
    print(f"   SAML client_id: {client.client_id}")

    # ── Step 3: Add as thirdparty provider on the tenant ─────────
    third_party_id = f"saml-{TENANT_ID}"
    print(f"3. Adding thirdparty provider '{third_party_id}' to tenant...")

    tp_result = await create_or_update_third_party_config(
        tenant_id=TENANT_ID,
        config=ProviderConfig(
            third_party_id=third_party_id,
            name="MockSAML",
            clients=[
                ProviderClientConfig(
                    client_id=client.client_id,
                ),
            ],
        ),
        skip_validation=True,
    )
    print(f"   Status: {tp_result.status}")

    # ── Done ─────────────────────────────────────────────────────
    print()
    print("Setup complete!")
    print(f"  Tenant ID:      {TENANT_ID}")
    print(f"  SAML Client ID: {client.client_id}")
    print(f"  ThirdParty ID:  {third_party_id}")
    print()
    print("You can now start the FastAPI app with:")
    print("  python main.py")


if __name__ == "__main__":
    asyncio.run(main())
