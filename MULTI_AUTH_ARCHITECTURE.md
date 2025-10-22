# Multi-Provider Authentication Architecture

## Overview

This document describes the architecture for extending the current WebAuthn-only implementation to support multiple authentication providers (SAML, OAuth2/OIDC) while maintaining backward compatibility.

## Current State

- **Authentication**: WebAuthn only (passwordless biometric)
- **Database**: User and WebAuthnCredential tables
- **Endpoints**: /register/* and /login/* specific to WebAuthn
- **JWT**: Generated after successful WebAuthn authentication

## Target Architecture

Allow users to authenticate via multiple providers:
- WebAuthn (TouchID/FaceID) - **existing**
- SAML (Enterprise SSO)
- OAuth2 (Social login - Google, GitHub, Microsoft)
- OpenID Connect (extends OAuth2 with identity layer)

### Key Goals

1. **Backward Compatibility**: Existing WebAuthn flows continue to work
2. **User Account Linking**: One user can have multiple auth methods (e.g., WebAuthn + Google OAuth)
3. **Seamless Experience**: Users choose their preferred login method
4. **Enterprise Ready**: Support SAML for corporate identity providers (Okta, Azure AD, OneLogin)

## Database Schema Changes

### New Tables

#### `auth_providers`
Tracks available authentication providers in the system.

```sql
CREATE TABLE auth_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,  -- "webauthn", "saml-okta", "oauth2-google", etc.
    type TEXT NOT NULL,  -- "webauthn", "saml", "oauth2", "oidc"
    enabled BOOLEAN DEFAULT TRUE,
    config JSON,  -- Provider-specific configuration
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Example records**:
```sql
INSERT INTO auth_providers VALUES
('webauthn', 'WebAuthn', 'webauthn', TRUE, '{}', '2025-01-01'),
('saml-okta', 'Okta SSO', 'saml', TRUE, '{"entity_id": "...", "sso_url": "..."}', '2025-01-01'),
('oauth2-google', 'Google', 'oauth2', TRUE, '{"client_id": "...", "auth_url": "..."}', '2025-01-01');
```

#### `user_auth_methods`
Links users to their authentication methods (many-to-many).

```sql
CREATE TABLE user_auth_methods (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    auth_provider_id TEXT NOT NULL REFERENCES auth_providers(id),
    external_id TEXT,  -- User ID from external provider (e.g., Google user ID)
    metadata JSON,  -- Provider-specific data (tokens, attributes, etc.)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    UNIQUE(user_id, auth_provider_id, external_id)
);
```

#### `saml_config`
SAML Service Provider configuration.

```sql
CREATE TABLE saml_config (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,  -- SP Entity ID
    acs_url TEXT NOT NULL,  -- Assertion Consumer Service URL
    sls_url TEXT,  -- Single Logout Service URL
    x509_cert TEXT,  -- SP certificate
    private_key TEXT,  -- SP private key (encrypted)
    idp_entity_id TEXT,  -- IdP Entity ID
    idp_sso_url TEXT,  -- IdP SSO URL
    idp_cert TEXT,  -- IdP certificate
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### `oauth_config`
OAuth2/OIDC configuration per provider.

```sql
CREATE TABLE oauth_config (
    id TEXT PRIMARY KEY,
    provider_name TEXT NOT NULL,  -- "google", "github", "microsoft", etc.
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,  -- Encrypted in production
    auth_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    userinfo_url TEXT,  -- For OIDC
    scopes TEXT,  -- Space-separated scopes
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Modified Tables

#### `users`
Add column to track primary authentication method:

```sql
ALTER TABLE users ADD COLUMN primary_auth_provider_id TEXT REFERENCES auth_providers(id);
```

#### `webauthn_credentials`
Add reference to auth provider (for backward compatibility):

```sql
ALTER TABLE webauthn_credentials ADD COLUMN auth_provider_id TEXT DEFAULT 'webauthn' REFERENCES auth_providers(id);
```

## API Endpoints

### Generic Multi-Provider Endpoints

#### `GET /auth/providers`
List available authentication methods.

**Response**:
```json
{
  "providers": [
    {
      "id": "webauthn",
      "name": "WebAuthn",
      "type": "webauthn",
      "description": "Sign in with TouchID, FaceID, or Windows Hello"
    },
    {
      "id": "saml-okta",
      "name": "Okta SSO",
      "type": "saml",
      "description": "Enterprise single sign-on"
    },
    {
      "id": "oauth2-google",
      "name": "Google",
      "type": "oauth2",
      "description": "Sign in with your Google account"
    }
  ]
}
```

#### `POST /auth/{provider_id}/initiate`
Generic authentication initiation.

**For WebAuthn** (`/auth/webauthn/initiate`):
- Routes to existing `/login/begin`
- Returns WebAuthn challenge

**For SAML** (`/auth/saml-okta/initiate`):
- Generates SAML AuthnRequest
- Returns redirect URL to IdP

**For OAuth2** (`/auth/oauth2-google/initiate`):
- Generates OAuth authorization URL with state parameter
- Returns redirect URL

#### `POST /auth/{provider_id}/complete`
Generic authentication completion.

**For WebAuthn**:
- Routes to existing `/login/complete`
- Verifies assertion, returns JWT

**For SAML**:
- Receives and validates SAML assertion
- Extracts user attributes
- Creates or links user account
- Returns JWT

**For OAuth2**:
- Exchanges authorization code for access token
- Fetches user info from provider
- Creates or links user account
- Returns JWT

### Account Linking Endpoints

#### `POST /auth/link/{provider_id}/initiate`
Link a new authentication method to existing account. **Requires JWT**.

**Request Headers**:
```
Authorization: Bearer <jwt-token>
```

**Response**: Provider-specific initiation data (challenge, redirect URL, etc.)

#### `POST /auth/link/{provider_id}/complete`
Complete linking of new authentication method. **Requires JWT**.

Creates record in `user_auth_methods` table.

### Backward Compatibility

Existing endpoints remain functional:
- `POST /register/begin` → Creates user with WebAuthn
- `POST /register/complete` → Completes WebAuthn registration
- `POST /login/begin` → Initiates WebAuthn login
- `POST /login/complete` → Completes WebAuthn login

These internally use the new provider abstraction with `provider_id="webauthn"`.

## Implementation Guide

### Phase 1: Provider Abstraction Layer

**File: `auth/providers/base.py`**

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel

class AuthProvider(ABC):
    """Base class for all authentication providers"""

    def __init__(self, provider_id: str, config: Dict[str, Any]):
        self.provider_id = provider_id
        self.config = config

    @abstractmethod
    async def initiate_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initiate authentication flow.
        Returns provider-specific challenge/redirect data.
        """
        pass

    @abstractmethod
    async def complete_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete authentication flow.
        Returns user data and any provider-specific metadata.
        """
        pass

    @abstractmethod
    def supports_registration(self) -> bool:
        """Whether this provider supports new user registration"""
        pass

    @abstractmethod
    async def get_user_identifier(self, auth_data: Dict[str, Any]) -> str:
        """
        Extract unique user identifier from auth data.
        Used for account linking.
        """
        pass
```

**File: `auth/providers/webauthn_provider.py`**

```python
from auth.providers.base import AuthProvider

class WebAuthnProvider(AuthProvider):
    """WebAuthn authentication provider"""

    async def initiate_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Call existing /login/begin logic
        # Return WebAuthn challenge options
        pass

    async def complete_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Call existing /login/complete logic
        # Return user data
        pass

    def supports_registration(self) -> bool:
        return True  # WebAuthn supports registration

    async def get_user_identifier(self, auth_data: Dict[str, Any]) -> str:
        return auth_data["email"]  # Email is unique identifier
```

### Phase 2: SAML Integration

**Dependencies**:
```
python3-saml==1.16.0
```

**File: `auth/providers/saml_provider.py`**

```python
from auth.providers.base import AuthProvider
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

class SAMLProvider(AuthProvider):
    """SAML 2.0 authentication provider"""

    async def initiate_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate SAML AuthnRequest and return redirect URL.
        """
        saml_auth = OneLogin_Saml2_Auth(self._get_request_data(), self.config)
        sso_url = saml_auth.login()

        return {
            "redirect_url": sso_url,
            "method": "redirect"
        }

    async def complete_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process SAML Response and extract user attributes.
        """
        saml_auth = OneLogin_Saml2_Auth(self._get_request_data(), self.config)
        saml_auth.process_response()

        if not saml_auth.is_authenticated():
            raise ValueError("SAML authentication failed")

        attributes = saml_auth.get_attributes()

        return {
            "external_id": saml_auth.get_nameid(),
            "email": attributes.get("email", [None])[0],
            "name": attributes.get("displayName", [None])[0],
            "attributes": attributes
        }

    def supports_registration(self) -> bool:
        return True  # SAML can create new users on first login

    async def get_user_identifier(self, auth_data: Dict[str, Any]) -> str:
        return auth_data["email"]
```

**Endpoints**:
```python
@app.get("/auth/saml/metadata")
async def saml_metadata():
    """Return SP metadata XML"""
    # Generate and return SAML metadata
    pass

@app.post("/auth/saml/acs")
async def saml_acs(request: Request):
    """Assertion Consumer Service - receives SAML response"""
    # Process SAML response
    # Create/link user account
    # Return JWT
    pass
```

### Phase 3: OAuth2/OIDC Integration

**Dependencies**:
```
authlib==1.3.0
```

**File: `auth/providers/oauth2_provider.py`**

```python
from auth.providers.base import AuthProvider
from authlib.integrations.starlette_client import OAuth

class OAuth2Provider(AuthProvider):
    """OAuth 2.0 / OpenID Connect provider"""

    async def initiate_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate OAuth authorization URL with state parameter.
        """
        oauth = OAuth()
        oauth.register(
            name=self.provider_id,
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            authorize_url=self.config["auth_url"],
            access_token_url=self.config["token_url"],
            client_kwargs={"scope": self.config["scopes"]}
        )

        redirect_uri = f"{ORIGIN}/auth/{self.provider_id}/callback"
        auth_url = await oauth.create_client(self.provider_id).authorize_redirect(
            redirect_uri=redirect_uri
        )

        return {
            "redirect_url": auth_url,
            "method": "redirect"
        }

    async def complete_auth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exchange code for token and fetch user info.
        """
        oauth = OAuth()
        # Exchange authorization code for access token
        token = await oauth.create_client(self.provider_id).authorize_access_token(data)

        # Fetch user info
        userinfo = await oauth.create_client(self.provider_id).parse_id_token(token)

        return {
            "external_id": userinfo["sub"],
            "email": userinfo["email"],
            "name": userinfo.get("name"),
            "tokens": token
        }

    def supports_registration(self) -> bool:
        return True

    async def get_user_identifier(self, auth_data: Dict[str, Any]) -> str:
        return auth_data["email"]
```

**Popular OAuth2 Providers Configuration**:

```python
OAUTH_PROVIDERS = {
    "google": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes": "openid email profile"
    },
    "github": {
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": "read:user user:email"
    },
    "microsoft": {
        "client_id": os.getenv("MICROSOFT_CLIENT_ID"),
        "client_secret": os.getenv("MICROSOFT_CLIENT_SECRET"),
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": "openid email profile"
    }
}
```

### Phase 4: Authentication Manager

**File: `auth/manager.py`**

```python
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from auth.providers.base import AuthProvider
from auth.providers.webauthn_provider import WebAuthnProvider
from auth.providers.saml_provider import SAMLProvider
from auth.providers.oauth2_provider import OAuth2Provider

class AuthenticationManager:
    """Orchestrates authentication across multiple providers"""

    def __init__(self, db: Session):
        self.db = db
        self.providers: Dict[str, AuthProvider] = {}
        self._load_providers()

    def _load_providers(self):
        """Load enabled providers from database"""
        # Query auth_providers table
        # Instantiate appropriate provider class for each
        pass

    async def initiate_auth(self, provider_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route authentication initiation to appropriate provider"""
        provider = self.providers.get(provider_id)
        if not provider:
            raise ValueError(f"Provider {provider_id} not found")

        return await provider.initiate_auth(data)

    async def complete_auth(self, provider_id: str, data: Dict[str, Any]) -> str:
        """
        Complete authentication and return JWT.
        Handles user creation/linking.
        """
        provider = self.providers.get(provider_id)
        if not provider:
            raise ValueError(f"Provider {provider_id} not found")

        # Get user data from provider
        auth_result = await provider.complete_auth(data)

        # Find or create user
        user = await self._find_or_create_user(provider_id, auth_result)

        # Record auth method usage
        await self._record_auth_method(user.id, provider_id, auth_result)

        # Generate JWT
        return create_access_token({
            "sub": user.id,
            "email": user.email,
            "name": user.name,
            "auth_provider": provider_id
        })

    async def _find_or_create_user(self, provider_id: str, auth_result: Dict[str, Any]) -> User:
        """
        Find existing user or create new one.
        Handles account linking based on email.
        """
        email = auth_result["email"]

        # Check if user exists
        user = self.db.query(User).filter(User.email == email).first()

        if user:
            # Existing user - link new auth method if not already linked
            return user
        else:
            # New user - create account
            user = User(
                email=email,
                name=auth_result.get("name", ""),
                date_of_birth=datetime.utcnow(),  # May need to collect separately
                job_title="",  # May need to collect separately
                primary_auth_provider_id=provider_id
            )
            self.db.add(user)
            self.db.commit()
            return user

    async def _record_auth_method(self, user_id: str, provider_id: str, auth_result: Dict[str, Any]):
        """Record or update user's auth method"""
        # Create or update user_auth_methods record
        pass
```

## Security Considerations

### JWT Claims

Update JWT to include authentication context:

```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "name": "Jane Doe",
  "auth_provider": "saml-okta",
  "auth_method": "saml",
  "amr": ["mfa", "pwd"],  // Authentication Methods References (OIDC standard)
  "iss": "auth-example-backend",
  "aud": "auth-example-backend",
  "iat": 1234567890,
  "exp": 1234571490
}
```

### Account Linking Security

1. **Email Verification**: When linking accounts, verify email ownership
2. **Existing Session Required**: Account linking requires valid JWT (user must be logged in)
3. **Confirmation Step**: Prompt user to confirm before linking new provider
4. **Audit Trail**: Log all account linking events

### SAML Security

1. **Signature Validation**: Always validate SAML assertion signatures
2. **Certificate Management**: Rotate certificates regularly
3. **Audience Restriction**: Validate audience matches SP entity ID
4. **Replay Prevention**: Check timestamp and NotOnOrAfter
5. **HTTPS Only**: SAML endpoints must use HTTPS in production

### OAuth2 Security

1. **State Parameter**: Use cryptographically random state to prevent CSRF
2. **PKCE**: Use Proof Key for Code Exchange for mobile/SPA clients
3. **Token Storage**: Never expose client_secret in frontend
4. **Scope Limiting**: Request minimal scopes needed
5. **Token Refresh**: Implement token refresh for long-lived sessions

## Migration Path

### Step 1: Database Migration
```sql
-- Add new tables
CREATE TABLE auth_providers ...
CREATE TABLE user_auth_methods ...
CREATE TABLE saml_config ...
CREATE TABLE oauth_config ...

-- Insert default WebAuthn provider
INSERT INTO auth_providers (id, name, type, enabled)
VALUES ('webauthn', 'WebAuthn', 'webauthn', TRUE);

-- Create user_auth_methods for existing users
INSERT INTO user_auth_methods (id, user_id, auth_provider_id, external_id, created_at)
SELECT
    uuid(),
    user_id,
    'webauthn',
    user_id,
    MIN(created_at)
FROM webauthn_credentials
GROUP BY user_id;
```

### Step 2: Code Refactoring
- Extract WebAuthn logic into WebAuthnProvider class
- Implement AuthenticationManager
- Update existing endpoints to use manager
- Add generic /auth/* endpoints

### Step 3: Add SAML Support
- Add SAML configuration UI/API
- Implement SAMLProvider
- Test with Okta/Azure AD

### Step 4: Add OAuth2 Support
- Configure OAuth2 providers (Google, GitHub, etc.)
- Implement OAuth2Provider
- Add frontend buttons for social login

## Configuration Examples

### Okta SAML Configuration

```python
{
    "entity_id": "http://localhost:8000/auth/saml/metadata",
    "acs_url": "http://localhost:8000/auth/saml/acs",
    "sls_url": "http://localhost:8000/auth/saml/sls",
    "idp_entity_id": "http://www.okta.com/exk...",
    "idp_sso_url": "https://company.okta.com/app/company_app/exk.../sso/saml",
    "idp_cert": "MIIDp... (base64 cert)"
}
```

### Azure AD OAuth2/OIDC Configuration

```python
{
    "client_id": "abc123...",
    "client_secret": "secret...",
    "auth_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    "token_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    "userinfo_url": "https://graph.microsoft.com/v1.0/me",
    "scopes": "openid email profile"
}
```

## Frontend Integration

Update the demo frontend to show provider selection:

```html
<div class="provider-buttons">
    <button onclick="loginWith('webauthn')">
        🔐 TouchID / FaceID
    </button>
    <button onclick="loginWith('saml-okta')">
        🏢 Company SSO
    </button>
    <button onclick="loginWith('oauth2-google')">
        🔵 Google
    </button>
    <button onclick="loginWith('oauth2-github')">
        ⚫ GitHub
    </button>
</div>
```

```javascript
async function loginWith(providerId) {
    // Call /auth/{providerId}/initiate
    const response = await fetch(`/auth/${providerId}/initiate`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({})
    });

    const data = await response.json();

    if (data.method === 'redirect') {
        // OAuth2/SAML redirect flow
        window.location.href = data.redirect_url;
    } else if (providerId === 'webauthn') {
        // WebAuthn browser API flow
        // ... existing WebAuthn logic
    }
}
```

## Testing Strategy

1. **Unit Tests**: Test each provider class independently
2. **Integration Tests**: Test full auth flows end-to-end
3. **SAML Testing**: Use SAMLtest.id for SAML validation
4. **OAuth2 Testing**: Use provider sandbox environments
5. **Account Linking Tests**: Test various linking scenarios

## Production Deployment Checklist

- [ ] Rotate all secrets (JWT_SECRET, client_secrets)
- [ ] Enable HTTPS for all endpoints
- [ ] Configure SAML certificates properly
- [ ] Set up OAuth2 redirect URIs in provider consoles
- [ ] Implement rate limiting
- [ ] Enable audit logging
- [ ] Test all providers in staging
- [ ] Document user-facing instructions
- [ ] Set up monitoring/alerting

## Conclusion

This architecture provides a flexible, scalable foundation for multi-provider authentication while maintaining the security and simplicity of the existing WebAuthn implementation. The provider abstraction pattern makes adding new authentication methods straightforward, and the account linking mechanism provides a seamless user experience across different login options.
