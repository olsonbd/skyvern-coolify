# Vaultwarden API Support

Vaultwarden is an alternative server implementation of the Bitwarden API. The [project wiki](https://github.com/dani-garcia/vaultwarden/wiki) lists the following supported features:

- Web interface equivalent to `https://vault.bitwarden.com/`
- Personal and organization vaults, including groups, event logs, and password sharing
- Collections, file attachments, folders, favorites, website icons, and Bitwarden Authenticator (TOTP)
- Bitwarden Send, Emergency Access, live sync via WebSocket, trash, and master password re-prompt
- Personal API key and two-step login methods (email, Duo, YubiKey, FIDO2)
- Username generator integrations and Directory Connector support
- Admin Password Reset and various enterprise policies

The wiki also describes features missing from Vaultwarden compared to the official server:

- Bitwarden Public API / Organization API key (only partial support for Directory Connector)
- Single Sign-On (SSO) and custom roles
- Certain enterprise policies such as requiring SSO authentication, vault timeout, and removing individual vault export

Vaultwarden does not mention support for the Bitwarden Vault Management API. The current codebase relies on that API, so some functionality may not work when switching to Vaultwarden.
