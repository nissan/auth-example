/**
 * API Client and Token Management
 * Handles HTTP requests and JWT token storage
 */

class AuthAPI {
    /**
     * Fetch user profile by ID
     * @param {string} userId - User's ID
     * @param {string} token - JWT access token
     * @returns {Promise<Object>} User profile data
     */
    async getUser(userId, token) {
        const response = await fetch(`/users/${userId}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to fetch user profile');
        }

        return await response.json();
    }

    /**
     * Check API health
     * @returns {Promise<boolean>}
     */
    async checkHealth() {
        try {
            const response = await fetch('/docs');
            return response.ok;
        } catch {
            return false;
        }
    }
}

class TokenManager {
    constructor() {
        this.TOKEN_KEY = 'webauthn_jwt';
        this.USER_ID_KEY = 'webauthn_user_id';
        this.USER_DATA_KEY = 'webauthn_user_data';
    }

    /**
     * Save authentication data to storage
     * @param {string} token - JWT access token
     * @param {Object} userData - User data from login/registration
     */
    saveAuth(token, userData) {
        try {
            sessionStorage.setItem(this.TOKEN_KEY, token);
            sessionStorage.setItem(this.USER_ID_KEY, userData.id);
            sessionStorage.setItem(this.USER_DATA_KEY, JSON.stringify(userData));
            console.log('Auth data saved to sessionStorage');
        } catch (error) {
            console.error('Failed to save auth data:', error);
        }
    }

    /**
     * Get JWT token from storage
     * @returns {string|null}
     */
    getToken() {
        return sessionStorage.getItem(this.TOKEN_KEY);
    }

    /**
     * Get user ID from storage
     * @returns {string|null}
     */
    getUserId() {
        return sessionStorage.getItem(this.USER_ID_KEY);
    }

    /**
     * Get user data from storage
     * @returns {Object|null}
     */
    getUserData() {
        const data = sessionStorage.getItem(this.USER_DATA_KEY);
        return data ? JSON.parse(data) : null;
    }

    /**
     * Check if token exists (not checking expiration)
     * @returns {boolean}
     */
    hasToken() {
        return this.getToken() !== null;
    }

    /**
     * Parse JWT token without verification
     * @param {string} token - JWT token
     * @returns {Object|null} Decoded payload
     */
    parseToken(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return null;
            }
            const payload = JSON.parse(atob(parts[1]));
            return payload;
        } catch (error) {
            console.error('Failed to parse token:', error);
            return null;
        }
    }

    /**
     * Check if token is expired
     * @param {string} token - JWT token (optional, uses stored token if not provided)
     * @returns {boolean}
     */
    isExpired(token = null) {
        const tokenToCheck = token || this.getToken();
        if (!tokenToCheck) {
            return true;
        }

        const payload = this.parseToken(tokenToCheck);
        if (!payload || !payload.exp) {
            return true;
        }

        // exp is in seconds, Date.now() is in milliseconds
        const expirationTime = payload.exp * 1000;
        return Date.now() >= expirationTime;
    }

    /**
     * Get time until token expiration
     * @param {string} token - JWT token (optional, uses stored token if not provided)
     * @returns {number} Milliseconds until expiration, or 0 if expired/invalid
     */
    getTimeUntilExpiration(token = null) {
        const tokenToCheck = token || this.getToken();
        if (!tokenToCheck) {
            return 0;
        }

        const payload = this.parseToken(tokenToCheck);
        if (!payload || !payload.exp) {
            return 0;
        }

        const expirationTime = payload.exp * 1000;
        const timeRemaining = expirationTime - Date.now();
        return Math.max(0, timeRemaining);
    }

    /**
     * Format expiration time as human-readable string
     * @param {string} token - JWT token (optional, uses stored token if not provided)
     * @returns {string} Formatted expiration time
     */
    formatExpiration(token = null) {
        const timeRemaining = this.getTimeUntilExpiration(token);
        if (timeRemaining === 0) {
            return 'Expired';
        }

        const minutes = Math.floor(timeRemaining / 60000);
        const seconds = Math.floor((timeRemaining % 60000) / 1000);

        if (minutes > 0) {
            return `${minutes} minute${minutes !== 1 ? 's' : ''} ${seconds} second${seconds !== 1 ? 's' : ''}`;
        } else {
            return `${seconds} second${seconds !== 1 ? 's' : ''}`;
        }
    }

    /**
     * Clear all authentication data
     */
    clear() {
        sessionStorage.removeItem(this.TOKEN_KEY);
        sessionStorage.removeItem(this.USER_ID_KEY);
        sessionStorage.removeItem(this.USER_DATA_KEY);
        console.log('Auth data cleared');
    }

    /**
     * Check if user is authenticated and token is valid
     * @returns {boolean}
     */
    isAuthenticated() {
        return this.hasToken() && !this.isExpired();
    }
}

// Export for use in other scripts
window.AuthAPI = AuthAPI;
window.TokenManager = TokenManager;
