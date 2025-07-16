import asyncio
import re
import urllib.parse
from enum import IntEnum, StrEnum
from typing import Tuple

import structlog
import tldextract
from pydantic import BaseModel

from skyvern.config import settings
from skyvern.exceptions import (
    BitwardenAccessDeniedError,
    BitwardenCreateCollectionError,
    BitwardenCreateCreditCardItemError,
    BitwardenCreateLoginItemError,
    BitwardenGetItemError,
    BitwardenListItemsError,
    BitwardenSecretError,
)
from skyvern.forge.sdk.api.aws import aws_client
from skyvern.forge.sdk.core.aiohttp_helper import aiohttp_delete, aiohttp_get_json, aiohttp_post
from skyvern.forge.sdk.schemas.credentials import (
    CredentialItem,
    CredentialType,
    CreditCardCredential,
    PasswordCredential,
)

LOG = structlog.get_logger()
if settings.VAULTWARDEN_SERVER:
    BITWARDEN_SERVER_BASE_URL = f"{settings.VAULTWARDEN_SERVER}:{settings.VAULTWARDEN_SERVER_PORT or 8000}"
else:
    BITWARDEN_SERVER_BASE_URL = f"{settings.BITWARDEN_SERVER}:{settings.BITWARDEN_SERVER_PORT or 8002}"


class BitwardenItemType(IntEnum):
    LOGIN = 1
    SECURE_NOTE = 2
    CREDIT_CARD = 3
    IDENTITY = 4


def get_bitwarden_item_type_code(item_type: BitwardenItemType) -> int:
    if item_type == BitwardenItemType.LOGIN:
        return 1
    elif item_type == BitwardenItemType.SECURE_NOTE:
        return 2
    elif item_type == BitwardenItemType.CREDIT_CARD:
        return 3
    elif item_type == BitwardenItemType.IDENTITY:
        return 4


def get_list_response_item_from_bitwarden_item(item: dict) -> CredentialItem:
    if item["type"] == BitwardenItemType.LOGIN:
        login = item["login"]
        totp = BitwardenService.extract_totp_secret(login.get("totp", ""))
        return CredentialItem(
            item_id=item["id"],
            credential=PasswordCredential(
                username=login["username"] or "",
                password=login["password"] or "",
                totp=totp,
            ),
            name=item["name"],
            credential_type=CredentialType.PASSWORD,
        )
    elif item["type"] == BitwardenItemType.CREDIT_CARD:
        card = item["card"]
        return CredentialItem(
            item_id=item["id"],
            credential=CreditCardCredential(
                card_holder_name=card["cardholderName"],
                card_number=card["number"],
                card_exp_month=card["expMonth"],
                card_exp_year=card["expYear"],
                card_cvv=card["code"],
                card_brand=card["brand"],
            ),
            name=item["name"],
            credential_type=CredentialType.CREDIT_CARD,
        )
    else:
        raise BitwardenGetItemError(f"Unsupported item type: {item['type']}")


def is_valid_email(email: str | None) -> bool:
    if not email:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


class BitwardenConstants(StrEnum):
    BW_ORGANIZATION_ID = "BW_ORGANIZATION_ID"
    BW_COLLECTION_IDS = "BW_COLLECTION_IDS"

    CLIENT_ID = "BW_CLIENT_ID"
    CLIENT_SECRET = "BW_CLIENT_SECRET"
    MASTER_PASSWORD = "BW_MASTER_PASSWORD"
    URL = "BW_URL"
    BW_COLLECTION_ID = "BW_COLLECTION_ID"
    IDENTITY_KEY = "BW_IDENTITY_KEY"
    BW_ITEM_ID = "BW_ITEM_ID"

    USERNAME = "BW_USERNAME"
    PASSWORD = "BW_PASSWORD"
    TOTP = "BW_TOTP"

    CREDIT_CARD_HOLDER_NAME = "BW_CREDIT_CARD_HOLDER_NAME"
    CREDIT_CARD_NUMBER = "BW_CREDIT_CARD_NUMBER"
    CREDIT_CARD_EXPIRATION_MONTH = "BW_CREDIT_CARD_EXPIRATION_MONTH"
    CREDIT_CARD_EXPIRATION_YEAR = "BW_CREDIT_CARD_EXPIRATION_YEAR"
    CREDIT_CARD_CVV = "BW_CREDIT_CARD_CVV"
    CREDIT_CARD_BRAND = "BW_CREDIT_CARD_BRAND"

    SKYVERN_AUTH_BITWARDEN_ORGANIZATION_ID = "SKYVERN_AUTH_BITWARDEN_ORGANIZATION_ID"
    SKYVERN_AUTH_BITWARDEN_MASTER_PASSWORD = "SKYVERN_AUTH_BITWARDEN_MASTER_PASSWORD"
    SKYVERN_AUTH_BITWARDEN_CLIENT_ID = "SKYVERN_AUTH_BITWARDEN_CLIENT_ID"
    SKYVERN_AUTH_BITWARDEN_CLIENT_SECRET = "SKYVERN_AUTH_BITWARDEN_CLIENT_SECRET"


class BitwardenQueryResult(BaseModel):
    credential: dict[str, str]
    uris: list[str]


class BitwardenService:
    @staticmethod
    def _extract_session_key(unlock_cmd_output: str) -> str | None:
        # Split the text by lines
        lines = unlock_cmd_output.split("\n")

        # Look for the line containing the BW_SESSION
        for line in lines:
            if 'BW_SESSION="' in line:
                # Find the start and end positions of the session key
                start = line.find('BW_SESSION="') + len('BW_SESSION="')
                end = line.rfind('"', start)
                return line[start:end]

        return None

    @staticmethod
    async def get_secret_value_from_url(
        master_password: str,
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
        url: str | None = None,
        collection_id: str | None = None,
        item_id: str | None = None,
        max_retries: int = settings.BITWARDEN_MAX_RETRIES,
        timeout: int = settings.BITWARDEN_TIMEOUT_SECONDS,
    ) -> dict[str, str]:
        """Get a login secret from Bitwarden via the Vault Management API."""

        fail_reasons: list[str] = []
        if not bw_organization_id and bw_collection_ids and collection_id not in bw_collection_ids:
            raise BitwardenAccessDeniedError()

        for i in range(max_retries):
            timeout = (i + 1) * timeout
            try:
                async with asyncio.timeout(timeout):
                    return await BitwardenService._get_secret_value_from_url_using_server(
                        master_password=master_password,
                        bw_organization_id=bw_organization_id,
                        bw_collection_ids=bw_collection_ids,
                        url=url,
                        collection_id=collection_id,
                        item_id=item_id,
                    )
            except BitwardenAccessDeniedError as e:
                raise e
            except Exception as e:
                LOG.info(
                    "Failed to get secret value from Bitwarden",
                    tried_times=i + 1,
                    exc_info=True,
                )
                fail_reasons.append(f"{type(e).__name__}: {str(e)}")

        raise BitwardenListItemsError(f"Bitwarden CLI failed after all retry attempts. Fail reasons: {fail_reasons}")

    @staticmethod
    def extract_totp_secret(totp_value: str) -> str:
        """
        Extract the TOTP secret from either a raw secret or a TOTP URI.

        Args:
            totp_value: Raw TOTP secret or URI (otpauth://totp/...)

        Returns:
            The extracted TOTP secret

        Example:
            >>> BitwardenService.extract_totp_secret("AAAAAABBBBBBB")
            "AAAAAABBBBBBB"
            >>> BitwardenService.extract_totp_secret("otpauth://totp/user@domain.com?secret=AAAAAABBBBBBB")
            "AAAAAABBBBBBB"
        """
        if not totp_value:
            return ""

        # Handle TOTP URI format
        if totp_value.startswith("otpauth://"):
            try:
                # Parse the URI to extract the secret
                query = urllib.parse.urlparse(totp_value).query
                params = dict(urllib.parse.parse_qsl(query))
                return params.get("secret", "")
            except Exception:
                LOG.error(
                    "Failed to parse TOTP URI",
                    totp_value=totp_value,
                    exc_info=True,
                )
                return ""

        return totp_value

    @staticmethod
    async def get_sensitive_information_from_identity(
        master_password: str,
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
        collection_id: str,
        identity_key: str,
        identity_fields: list[str],
        remaining_retries: int = settings.BITWARDEN_MAX_RETRIES,
        timeout: int = settings.BITWARDEN_TIMEOUT_SECONDS,
        fail_reasons: list[str] = [],
    ) -> dict[str, str]:
        """Get sensitive information via the Vault Management API."""
        if not bw_organization_id and bw_collection_ids and collection_id not in bw_collection_ids:
            raise BitwardenAccessDeniedError()
        try:
            async with asyncio.timeout(timeout):
                return await BitwardenService._get_sensitive_information_from_identity(
                    master_password=master_password,
                    bw_organization_id=bw_organization_id,
                    bw_collection_ids=bw_collection_ids,
                    collection_id=collection_id,
                    identity_key=identity_key,
                    identity_fields=identity_fields,
                )
        except BitwardenAccessDeniedError as e:
            raise e
        except Exception as e:
            if remaining_retries <= 0:
                raise BitwardenListItemsError(
                    f"Bitwarden CLI failed after all retry attempts. Fail reasons: {fail_reasons}"
                )

            remaining_retries -= 1
            LOG.info("Retrying to get sensitive information from Bitwarden", remaining_retries=remaining_retries)
            return await BitwardenService.get_sensitive_information_from_identity(
                master_password=master_password,
                bw_organization_id=bw_organization_id,
                bw_collection_ids=bw_collection_ids,
                collection_id=collection_id,
                identity_key=identity_key,
                identity_fields=identity_fields,
                remaining_retries=remaining_retries,
                # Double the timeout for the next retry
                timeout=timeout * 2,
                fail_reasons=fail_reasons + [f"{type(e).__name__}: {str(e)}"],
            )

    @staticmethod
    async def _get_sensitive_information_from_identity(
        master_password: str,
        collection_id: str,
        identity_key: str,
        identity_fields: list[str],
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
    ) -> dict[str, str]:
        """Get sensitive information using the Vault Management API."""
        await BitwardenService._unlock_using_server(master_password)

        if not bw_organization_id and not collection_id:
            raise BitwardenAccessDeniedError()

        params = {"search": identity_key, "collectionId": collection_id}
        if bw_organization_id:
            params["organizationId"] = bw_organization_id

        query = urllib.parse.urlencode(params)
        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/list/object/items?{query}")
        if not response or response.get("success") is False:
            raise BitwardenListItemsError("Failed to get collection items")

        items = response["data"]["data"]
        if not items:
            raise BitwardenListItemsError(
                f"No items found in Bitwarden for identity key: {identity_key} in collection with ID: {collection_id}"
            )

        identity_item = items[0]

        sensitive_information: dict[str, str] = {}
        for field in identity_fields:
            for item in identity_item.get("fields", []):
                if item.get("name") == field:
                    sensitive_information[field] = item.get("value", "")
                    break

            if (
                "identity" in identity_item
                and field in identity_item["identity"]
                and field not in sensitive_information
            ):
                sensitive_information[field] = identity_item["identity"][field]

        return sensitive_information

    @staticmethod
    async def _get_credit_card_data(
        master_password: str,
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
        collection_id: str,
        item_id: str,
    ) -> dict[str, str]:
        """Get credit card data using the Vault Management API."""
        await BitwardenService._unlock_using_server(master_password)

        if not bw_organization_id and not collection_id:
            LOG.error("No collection ID or organization ID provided -- this is required")
            raise BitwardenAccessDeniedError()

        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/item/{item_id}")
        if not response or response.get("success") is False:
            raise BitwardenListItemsError(f"Failed to get item with ID: {item_id}")

        item = response["data"]

        if bw_organization_id and item.get("organizationId") != bw_organization_id:
            raise BitwardenAccessDeniedError()

        if bw_collection_ids:
            item_collection_ids = item.get("collectionIds")
            if item_collection_ids and collection_id not in bw_collection_ids:
                raise BitwardenAccessDeniedError()

        if item["type"] != get_bitwarden_item_type_code(BitwardenItemType.CREDIT_CARD):
            raise BitwardenListItemsError(f"Item with ID: {item_id} is not a credit card type")

        credit_card_data = item["card"]

        return {
            BitwardenConstants.CREDIT_CARD_HOLDER_NAME: credit_card_data["cardholderName"],
            BitwardenConstants.CREDIT_CARD_NUMBER: credit_card_data["number"],
            BitwardenConstants.CREDIT_CARD_EXPIRATION_MONTH: credit_card_data["expMonth"],
            BitwardenConstants.CREDIT_CARD_EXPIRATION_YEAR: credit_card_data["expYear"],
            BitwardenConstants.CREDIT_CARD_CVV: credit_card_data["code"],
            BitwardenConstants.CREDIT_CARD_BRAND: credit_card_data["brand"],
        }

    @staticmethod
    async def get_credit_card_data(
        master_password: str,
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
        collection_id: str,
        item_id: str,
        remaining_retries: int = settings.BITWARDEN_MAX_RETRIES,
        fail_reasons: list[str] = [],
    ) -> dict[str, str]:
        """Get credit card data via the Vault Management API."""
        try:
            async with asyncio.timeout(settings.BITWARDEN_TIMEOUT_SECONDS):
                return await BitwardenService._get_credit_card_data(
                    master_password=master_password,
                    bw_organization_id=bw_organization_id,
                    bw_collection_ids=bw_collection_ids,
                    collection_id=collection_id,
                    item_id=item_id,
                )
        except BitwardenAccessDeniedError as e:
            raise e
        except Exception as e:
            if remaining_retries <= 0:
                raise BitwardenListItemsError(
                    f"Bitwarden CLI failed after all retry attempts. Fail reasons: {fail_reasons}"
                )

            remaining_retries -= 1
            LOG.info("Retrying to get credit card data from Bitwarden", remaining_retries=remaining_retries)
            return await BitwardenService.get_credit_card_data(
                master_password=master_password,
                bw_organization_id=bw_organization_id,
                bw_collection_ids=bw_collection_ids,
                collection_id=collection_id,
                item_id=item_id,
                remaining_retries=remaining_retries,
                fail_reasons=fail_reasons + [f"{type(e).__name__}: {str(e)}"],
            )

    @staticmethod
    async def _unlock_using_server(master_password: str) -> None:
        status_response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/status")
        status = status_response["data"]["template"]["status"]
        if status != "unlocked":
            await aiohttp_post(f"{BITWARDEN_SERVER_BASE_URL}/unlock", data={"password": master_password})

    @staticmethod
    async def _get_login_item_by_id_using_server(item_id: str) -> PasswordCredential:
        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/item/{item_id}")
        if not response or response.get("success") is False:
            raise BitwardenGetItemError(f"Failed to get login item by ID: {item_id}")

        login = response["data"]["login"]
        totp = BitwardenService.extract_totp_secret(login.get("totp", ""))
        if not login:
            raise BitwardenGetItemError(f"Item with ID: {item_id} is not a login item")

        return PasswordCredential(
            username=login["username"] or "",
            password=login["password"] or "",
            totp=totp,
        )

    @staticmethod
    async def _get_secret_value_from_url_using_server(
        master_password: str,
        bw_organization_id: str | None,
        bw_collection_ids: list[str] | None,
        url: str | None = None,
        collection_id: str | None = None,
        item_id: str | None = None,
    ) -> dict[str, str]:
        await BitwardenService._unlock_using_server(master_password)

        if item_id:
            login_item = await BitwardenService._get_login_item_by_id_using_server(item_id)
            return {
                BitwardenConstants.USERNAME: login_item.username,
                BitwardenConstants.PASSWORD: login_item.password,
                BitwardenConstants.TOTP: login_item.totp or "",
            }

        if not url:
            raise BitwardenGetItemError("No url or item ID provided")

        extract_url = tldextract.extract(url)
        domain = extract_url.domain

        params = {"search": domain}
        if bw_organization_id:
            params["organizationId"] = bw_organization_id
        if collection_id:
            params["collectionId"] = collection_id
        if not bw_organization_id and not collection_id:
            LOG.error("No collection ID or organization ID provided -- this is required")
            raise BitwardenListItemsError("No collection ID or organization ID provided -- this is required")

        query = urllib.parse.urlencode(params)
        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/list/object/items?{query}")
        if not response or response.get("success") is False:
            raise BitwardenListItemsError("Failed to get collection items")

        items = response["data"]["data"]

        if bw_organization_id and collection_id:
            items = [item for item in items if "collectionIds" in item and collection_id in item["collectionIds"]]

        if not items:
            collection_id_str = f" in collection with ID: {collection_id}" if collection_id else ""
            raise BitwardenListItemsError(f"No items found in Bitwarden for URL: {url}{collection_id_str}")

        bitwarden_result: list[BitwardenQueryResult] = []
        for item in items:
            if "login" not in item:
                continue

            login = item["login"]
            totp = BitwardenService.extract_totp_secret(login.get("totp", ""))

            bitwarden_result.append(
                BitwardenQueryResult(
                    credential={
                        BitwardenConstants.USERNAME: login.get("username", ""),
                        BitwardenConstants.PASSWORD: login.get("password", ""),
                        BitwardenConstants.TOTP: totp,
                    },
                    uris=[uri.get("uri") for uri in login.get("uris", []) if "uri" in uri],
                )
            )

        if len(bitwarden_result) == 0:
            return {}

        if len(bitwarden_result) == 1:
            return bitwarden_result[0].credential

        for single_result in bitwarden_result:
            if is_valid_email(single_result.credential.get(BitwardenConstants.USERNAME)):
                for uri in single_result.uris:
                    if extract_url.registered_domain == tldextract.extract(uri).registered_domain:
                        return single_result.credential

        LOG.warning("No credential in Bitwarden matches the rule, returning the first match")
        return bitwarden_result[0].credential

    @staticmethod
    async def _create_login_item_using_server(
        bw_organization_id: str,
        collection_id: str,
        name: str,
        credential: PasswordCredential,
    ) -> str:
        item_template = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/template/item")
        login_template = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/template/item.login")

        item_template = item_template["data"]["template"]
        login_template = login_template["data"]["template"]

        login_template["username"] = credential.username
        login_template["password"] = credential.password
        login_template["totp"] = credential.totp

        item_template["type"] = get_bitwarden_item_type_code(BitwardenItemType.LOGIN)
        item_template["name"] = name
        item_template["login"] = login_template
        item_template["collectionIds"] = [collection_id]
        item_template["organizationId"] = bw_organization_id

        response = await aiohttp_post(f"{BITWARDEN_SERVER_BASE_URL}/object/item", data=item_template)
        if not response or response.get("success") is False:
            raise BitwardenCreateLoginItemError("Failed to create login item")

        return response["data"]["id"]

    @staticmethod
    async def _create_credit_card_item_using_server(
        bw_organization_id: str,
        collection_id: str,
        name: str,
        credential: CreditCardCredential,
    ) -> str:
        item_template = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/template/item")
        credit_card_template = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/template/item.card")

        item_template = item_template["data"]["template"]
        credit_card_template = credit_card_template["data"]["template"]

        credit_card_template["cardholderName"] = credential.card_holder_name
        credit_card_template["number"] = credential.card_number
        credit_card_template["expMonth"] = credential.card_exp_month
        credit_card_template["expYear"] = credential.card_exp_year
        credit_card_template["code"] = credential.card_cvv
        credit_card_template["brand"] = credential.card_brand

        item_template["type"] = get_bitwarden_item_type_code(BitwardenItemType.CREDIT_CARD)
        item_template["name"] = name
        item_template["card"] = credit_card_template
        item_template["collectionIds"] = [collection_id]
        item_template["organizationId"] = bw_organization_id

        response = await aiohttp_post(f"{BITWARDEN_SERVER_BASE_URL}/object/item", data=item_template)
        if not response or response.get("success") is False:
            raise BitwardenCreateCreditCardItemError("Failed to create credit card item")

        return response["data"]["id"]

    @staticmethod
    async def create_credential_item(
        collection_id: str,
        name: str,
        credential: PasswordCredential | CreditCardCredential,
    ) -> str:
        try:
            master_password, bw_organization_id, _, _ = await BitwardenService._get_skyvern_auth_secrets()

            await BitwardenService._unlock_using_server(master_password)
            if isinstance(credential, PasswordCredential):
                return await BitwardenService._create_login_item_using_server(
                    bw_organization_id=bw_organization_id,
                    collection_id=collection_id,
                    name=name,
                    credential=credential,
                )
            else:
                return await BitwardenService._create_credit_card_item_using_server(
                    bw_organization_id=bw_organization_id,
                    collection_id=collection_id,
                    name=name,
                    credential=credential,
                )
        except Exception as e:
            raise e

    @staticmethod
    async def _get_skyvern_auth_master_password() -> str:
        master_password = settings.SKYVERN_AUTH_BITWARDEN_MASTER_PASSWORD
        if not master_password:
            master_password = await aws_client.get_secret(BitwardenConstants.SKYVERN_AUTH_BITWARDEN_MASTER_PASSWORD)
        if not master_password:
            raise BitwardenSecretError("Skyvern auth master password is not set")
        return master_password

    @staticmethod
    async def _get_skyvern_auth_organization_id() -> str:
        bw_organization_id = settings.SKYVERN_AUTH_BITWARDEN_ORGANIZATION_ID
        if not bw_organization_id:
            bw_organization_id = await aws_client.get_secret(BitwardenConstants.SKYVERN_AUTH_BITWARDEN_ORGANIZATION_ID)
        if not bw_organization_id:
            raise BitwardenSecretError("Skyvern auth organization ID is not set")
        return bw_organization_id

    @staticmethod
    async def _get_skyvern_auth_client_id() -> str:
        client_id = settings.SKYVERN_AUTH_BITWARDEN_CLIENT_ID
        if not client_id:
            client_id = await aws_client.get_secret(BitwardenConstants.SKYVERN_AUTH_BITWARDEN_CLIENT_ID)
        if not client_id:
            raise BitwardenSecretError("Skyvern auth client ID is not set")
        return client_id

    @staticmethod
    async def _get_skyvern_auth_client_secret() -> str:
        client_secret = settings.SKYVERN_AUTH_BITWARDEN_CLIENT_SECRET
        if not client_secret:
            client_secret = await aws_client.get_secret(BitwardenConstants.SKYVERN_AUTH_BITWARDEN_CLIENT_SECRET)
        if not client_secret:
            raise BitwardenSecretError("Skyvern auth client secret is not set")
        return client_secret

    @staticmethod
    async def create_collection(
        name: str,
    ) -> str:
        """
        Create a collection in Bitwarden and return the collection ID.
        """
        try:
            master_password, bw_organization_id, _, _ = await BitwardenService._get_skyvern_auth_secrets()

            await BitwardenService._unlock_using_server(master_password)
            return await BitwardenService._create_collection_using_server(bw_organization_id, name)

        except Exception as e:
            raise e

    @staticmethod
    async def _create_collection_using_server(bw_organization_id: str, name: str) -> str:
        collection_template_response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/template/collection")
        collection_template = collection_template_response["data"]["template"]

        collection_template["name"] = name
        collection_template["organizationId"] = bw_organization_id

        response = await aiohttp_post(
            f"{BITWARDEN_SERVER_BASE_URL}/object/org-collection?organizationId={bw_organization_id}",
            data=collection_template,
        )
        if not response or response.get("success") is False:
            raise BitwardenCreateCollectionError("Failed to create collection")

        return response["data"]["id"]

    @staticmethod
    async def _get_skyvern_auth_secrets() -> Tuple[str, str, str, str]:
        master_password, bw_organization_id, client_id, client_secret = await asyncio.gather(
            BitwardenService._get_skyvern_auth_master_password(),
            BitwardenService._get_skyvern_auth_organization_id(),
            BitwardenService._get_skyvern_auth_client_id(),
            BitwardenService._get_skyvern_auth_client_secret(),
        )
        return master_password, bw_organization_id, client_id, client_secret

    @staticmethod
    async def get_items_by_item_ids(
        item_ids: list[str],
    ) -> list[CredentialItem]:
        try:
            master_password, _, _, _ = await BitwardenService._get_skyvern_auth_secrets()
            await BitwardenService._unlock_using_server(master_password)
            return await BitwardenService._get_items_by_item_ids_using_server(item_ids)
        except Exception as e:
            raise e

    @staticmethod
    async def _get_items_by_item_ids_using_server(item_ids: list[str]) -> list[CredentialItem]:
        responses = await asyncio.gather(
            *[aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/item/{item_id}") for item_id in item_ids]
        )
        if not responses or any(response.get("success") is False for response in responses):
            raise BitwardenGetItemError("Failed to get collection items")

        return [get_list_response_item_from_bitwarden_item(response["data"]) for response in responses]

    @staticmethod
    async def get_collection_items(
        collection_id: str,
    ) -> list[CredentialItem]:
        try:
            master_password, _, _, _ = await BitwardenService._get_skyvern_auth_secrets()
            await BitwardenService._unlock_using_server(master_password)
            return await BitwardenService._get_collection_items_using_server(collection_id)
        except Exception as e:
            raise e

    @staticmethod
    async def _get_collection_items_using_server(collection_id: str) -> list[CredentialItem]:
        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/list/object/items?collectionId={collection_id}")
        if not response or response.get("success") is False:
            raise BitwardenGetItemError("Failed to get collection items")

        items = response["data"]["data"]
        items = map(lambda item: get_list_response_item_from_bitwarden_item(item), items)
        return list(items)

    @staticmethod
    async def get_credential_item(
        item_id: str,
    ) -> CredentialItem:
        try:
            master_password, _, _, _ = await BitwardenService._get_skyvern_auth_secrets()
            await BitwardenService._unlock_using_server(master_password)
            return await BitwardenService._get_credential_item_by_id_using_server(item_id)
        except Exception as e:
            raise e

    @staticmethod
    async def _get_credential_item_by_id_using_server(item_id: str) -> CredentialItem:
        response = await aiohttp_get_json(f"{BITWARDEN_SERVER_BASE_URL}/object/item/{item_id}")
        if not response or response.get("success") is False:
            raise BitwardenGetItemError(f"Failed to get credential item by ID: {item_id}")

        if response["data"]["type"] == BitwardenItemType.LOGIN:
            login_item = response["data"]["login"]
            name = response["data"]["name"]
            return CredentialItem(
                item_id=item_id,
                credential_type=CredentialType.PASSWORD,
                name=name,
                credential=PasswordCredential(
                    username=login_item["username"] or "",
                    password=login_item["password"] or "",
                    totp=login_item["totp"],
                ),
            )
        elif response["data"]["type"] == BitwardenItemType.CREDIT_CARD:
            credit_card_item = response["data"]["card"]
            name = response["data"]["name"]
            return CredentialItem(
                item_id=item_id,
                credential_type=CredentialType.CREDIT_CARD,
                name=name,
                credential=CreditCardCredential(
                    card_holder_name=credit_card_item["cardholderName"],
                    card_number=credit_card_item["number"],
                    card_exp_month=credit_card_item["expMonth"],
                    card_exp_year=credit_card_item["expYear"],
                    card_cvv=credit_card_item["code"],
                    card_brand=credit_card_item["brand"],
                ),
            )
        else:
            raise BitwardenGetItemError(f"Unsupported item type: {response['data']['type']}")

    @staticmethod
    async def delete_credential_item(
        item_id: str,
    ) -> None:
        try:
            master_password, _, _, _ = await BitwardenService._get_skyvern_auth_secrets()
            await BitwardenService._unlock_using_server(master_password)
            await BitwardenService._delete_credential_item_using_server(item_id)
        except Exception as e:
            raise e

    @staticmethod
    async def _delete_credential_item_using_server(item_id: str) -> None:
        await aiohttp_delete(f"{BITWARDEN_SERVER_BASE_URL}/object/item/{item_id}")
