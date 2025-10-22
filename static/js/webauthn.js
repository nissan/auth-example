/**
 * WebAuthn Client Library
 * Handles browser WebAuthn API calls and base64url encoding/decoding
 */

class WebAuthnClient {
    /**
     * Register a new user with WebAuthn
     * @param {Object} userData - User registration data
     * @returns {Promise<Object>} User object from server
     */
    async register(userData) {
        try {
            // Step 1: Get registration options from server
            const optionsResponse = await fetch('/register/begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });

            if (!optionsResponse.ok) {
                const error = await optionsResponse.json();
                throw new Error(error.detail || 'Registration initiation failed');
            }

            const options = await optionsResponse.json();

            // Step 2: Prepare credential creation options
            const credentialOptions = this._parseCredentialCreationOptions(options);

            // Step 3: Call browser WebAuthn API
            const credential = await navigator.credentials.create({
                publicKey: credentialOptions
            });

            if (!credential) {
                throw new Error('Failed to create credential. User may have cancelled.');
            }

            // Step 4: Encode credential for transmission
            const credentialJSON = this._encodeCredential(credential);

            // Step 5: Send credential to server for verification
            const completeResponse = await fetch('/register/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: userData.email,
                    credential: credentialJSON
                })
            });

            if (!completeResponse.ok) {
                const error = await completeResponse.json();
                throw new Error(error.detail || 'Registration completion failed');
            }

            return await completeResponse.json();
        } catch (error) {
            console.error('WebAuthn registration error:', error);
            throw error;
        }
    }

    /**
     * Authenticate an existing user with WebAuthn
     * @param {string} email - User's email
     * @returns {Promise<Object>} Authentication response with JWT token
     */
    async login(email) {
        try {
            // Step 1: Get authentication options from server
            const optionsResponse = await fetch('/login/begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });

            if (!optionsResponse.ok) {
                const error = await optionsResponse.json();
                throw new Error(error.detail || 'Login initiation failed');
            }

            const options = await optionsResponse.json();

            // Step 2: Prepare credential request options
            const credentialOptions = this._parseCredentialRequestOptions(options);

            // Step 3: Call browser WebAuthn API
            const assertion = await navigator.credentials.get({
                publicKey: credentialOptions
            });

            if (!assertion) {
                throw new Error('Failed to get assertion. User may have cancelled.');
            }

            // Step 4: Encode assertion for transmission
            const assertionJSON = this._encodeAssertion(assertion);

            // Step 5: Send assertion to server for verification
            const completeResponse = await fetch('/login/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    assertion: assertionJSON
                })
            });

            if (!completeResponse.ok) {
                const error = await completeResponse.json();
                throw new Error(error.detail || 'Login completion failed');
            }

            return await completeResponse.json();
        } catch (error) {
            console.error('WebAuthn login error:', error);
            throw error;
        }
    }

    /**
     * Parse credential creation options from server
     * @private
     */
    _parseCredentialCreationOptions(options) {
        const publicKey = options.publicKey;

        return {
            challenge: this._base64urlToBuffer(publicKey.challenge),
            rp: publicKey.rp,
            user: {
                id: this._base64urlToBuffer(publicKey.user.id),
                name: publicKey.user.name,
                displayName: publicKey.user.displayName
            },
            pubKeyCredParams: publicKey.pubKeyCredParams,
            timeout: publicKey.timeout,
            authenticatorSelection: publicKey.authenticatorSelection,
            attestation: publicKey.attestation || 'none'
        };
    }

    /**
     * Parse credential request options from server
     * @private
     */
    _parseCredentialRequestOptions(options) {
        const publicKey = options.publicKey;

        return {
            challenge: this._base64urlToBuffer(publicKey.challenge),
            timeout: publicKey.timeout,
            rpId: publicKey.rpId,
            allowCredentials: publicKey.allowCredentials.map(cred => ({
                type: cred.type,
                id: this._base64urlToBuffer(cred.id)
            })),
            userVerification: publicKey.userVerification || 'required'
        };
    }

    /**
     * Encode credential for transmission to server
     * @private
     */
    _encodeCredential(credential) {
        return {
            id: this._bufferToBase64url(credential.rawId),
            rawId: this._bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: this._bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: this._bufferToBase64url(credential.response.attestationObject)
            }
        };
    }

    /**
     * Encode assertion for transmission to server
     * @private
     */
    _encodeAssertion(assertion) {
        return {
            id: this._bufferToBase64url(assertion.rawId),
            rawId: this._bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: this._bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: this._bufferToBase64url(assertion.response.clientDataJSON),
                signature: this._bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? this._bufferToBase64url(assertion.response.userHandle) : null
            }
        };
    }

    /**
     * Convert base64url string to ArrayBuffer
     * @private
     */
    _base64urlToBuffer(base64url) {
        // Add padding if needed
        const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;

        const binary = atob(base64);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
    }

    /**
     * Convert ArrayBuffer to base64url string
     * @private
     */
    _bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    /**
     * Check if WebAuthn is supported in the current browser
     * @returns {boolean}
     */
    static isSupported() {
        return window.PublicKeyCredential !== undefined &&
               navigator.credentials !== undefined;
    }

    /**
     * Check if platform authenticator (TouchID, FaceID, Windows Hello) is available
     * @returns {Promise<boolean>}
     */
    static async isPlatformAuthenticatorAvailable() {
        if (!this.isSupported()) {
            return false;
        }
        try {
            return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch {
            return false;
        }
    }
}

// Export for use in other scripts
window.WebAuthnClient = WebAuthnClient;
