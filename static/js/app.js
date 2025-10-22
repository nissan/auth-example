/**
 * Main Application Logic
 * Handles UI state, form submissions, and user interactions
 */

class WebAuthnApp {
    constructor() {
        this.webauthnClient = new WebAuthnClient();
        this.authAPI = new AuthAPI();
        this.tokenManager = new TokenManager();

        this.state = {
            currentView: 'landing',
            isLoading: false,
            user: null
        };

        this.init();
    }

    /**
     * Initialize the application
     */
    async init() {
        console.log('Initializing WebAuthn Demo App...');

        // Check WebAuthn support
        if (!WebAuthnClient.isSupported()) {
            this.showError('WebAuthn is not supported in your browser. Please use Chrome, Safari, Edge, or Firefox.');
            return;
        }

        // Check for existing session
        if (this.tokenManager.isAuthenticated()) {
            console.log('Found existing session, loading profile...');
            await this.loadProfile();
        }

        // Setup event listeners
        this.setupEventListeners();

        // Check platform authenticator availability
        const hasAuthenticator = await WebAuthnClient.isPlatformAuthenticatorAvailable();
        if (!hasAuthenticator) {
            this.showWarning('No biometric authenticator detected. You may need TouchID, FaceID, Windows Hello, or a security key.');
        }

        console.log('App initialized successfully');
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const tab = e.target.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Registration form
        const regForm = document.getElementById('register-form');
        if (regForm) {
            regForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegistration(e.target);
            });
        }

        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin(e.target);
            });
        }

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.handleLogout();
            });
        }
    }

    /**
     * Handle user registration
     */
    async handleRegistration(form) {
        try {
            const formData = new FormData(form);
            const userData = {
                name: formData.get('name'),
                email: formData.get('email'),
                date_of_birth: formData.get('date_of_birth') + 'T00:00:00Z',
                job_title: formData.get('job_title')
            };

            this.showLoading('Requesting biometric authentication...');

            // Call WebAuthn registration
            const user = await this.webauthnClient.register(userData);

            this.showSuccess(`Welcome, ${user.name}! Your account has been created.`);

            // For registration, we need to login to get a JWT token
            this.showLoading('Logging you in...');
            await this.handleAutoLogin(userData.email);

        } catch (error) {
            this.hideLoading();
            this.showError(`Registration failed: ${error.message}`);
        }
    }

    /**
     * Auto-login after registration
     */
    async handleAutoLogin(email) {
        try {
            const authResponse = await this.webauthnClient.login(email);

            // Save token and user data
            this.tokenManager.saveAuth(authResponse.access_token, authResponse.user);

            this.hideLoading();
            this.showSuccess('Login successful!');

            // Load and display profile
            await this.loadProfile();

        } catch (error) {
            this.hideLoading();
            this.showError(`Auto-login failed: ${error.message}. Please try logging in manually.`);
        }
    }

    /**
     * Handle user login
     */
    async handleLogin(form) {
        try {
            const formData = new FormData(form);
            const email = formData.get('email');

            this.showLoading('Requesting biometric authentication...');

            // Call WebAuthn login
            const authResponse = await this.webauthnClient.login(email);

            // Save token and user data
            this.tokenManager.saveAuth(authResponse.access_token, authResponse.user);

            this.hideLoading();
            this.showSuccess(`Welcome back, ${authResponse.user.name}!`);

            // Load and display profile
            await this.loadProfile();

        } catch (error) {
            this.hideLoading();
            this.showError(`Login failed: ${error.message}`);
        }
    }

    /**
     * Load user profile
     */
    async loadProfile() {
        try {
            const token = this.tokenManager.getToken();
            const userId = this.tokenManager.getUserId();

            if (!token || !userId) {
                throw new Error('No authentication data found');
            }

            // Fetch user profile from API
            const user = await this.authAPI.getUser(userId, token);

            // Update state and UI
            this.state.user = user;
            this.displayProfile(user, token);
            this.switchView('profile');

        } catch (error) {
            console.error('Failed to load profile:', error);
            this.tokenManager.clear();
            this.showError('Session expired or invalid. Please login again.');
            this.switchView('landing');
        }
    }

    /**
     * Display user profile in UI
     */
    displayProfile(user, token) {
        document.getElementById('profile-name').textContent = user.name;
        document.getElementById('profile-email').textContent = user.email;
        document.getElementById('profile-dob').textContent = new Date(user.date_of_birth).toLocaleDateString();
        document.getElementById('profile-job').textContent = user.job_title;
        document.getElementById('profile-created').textContent = new Date(user.created_at).toLocaleDateString();

        // Display token expiration with countdown
        this.updateExpirationDisplay(token);

        // Update expiration every second
        if (this.expirationInterval) {
            clearInterval(this.expirationInterval);
        }
        this.expirationInterval = setInterval(() => {
            if (this.tokenManager.isExpired(token)) {
                clearInterval(this.expirationInterval);
                this.showError('Session expired. Please login again.');
                this.handleLogout();
            } else {
                this.updateExpirationDisplay(token);
            }
        }, 1000);
    }

    /**
     * Update expiration time display
     */
    updateExpirationDisplay(token) {
        const expiresElement = document.getElementById('profile-expires');
        const formatted = this.tokenManager.formatExpiration(token);
        expiresElement.textContent = formatted;

        // Add warning class if less than 5 minutes
        const timeRemaining = this.tokenManager.getTimeUntilExpiration(token);
        if (timeRemaining < 300000) { // 5 minutes
            expiresElement.style.color = '#d32f2f';
        } else {
            expiresElement.style.color = '';
        }
    }

    /**
     * Handle user logout
     */
    handleLogout() {
        if (this.expirationInterval) {
            clearInterval(this.expirationInterval);
        }
        this.tokenManager.clear();
        this.state.user = null;
        this.switchView('landing');
        this.showSuccess('You have been logged out.');
    }

    /**
     * Switch between views (landing, profile)
     */
    switchView(viewName) {
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });

        const targetView = document.getElementById(`${viewName}-view`);
        if (targetView) {
            targetView.classList.add('active');
        }

        this.state.currentView = viewName;
    }

    /**
     * Switch between tabs (register, login)
     */
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });
        const activeButton = document.querySelector(`.tab-button[data-tab="${tabName}"]`);
        if (activeButton) {
            activeButton.classList.add('active');
        }

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        const activeContent = document.getElementById(`${tabName}-tab`);
        if (activeContent) {
            activeContent.classList.add('active');
        }
    }

    /**
     * Show loading overlay
     */
    showLoading(message = 'Processing...') {
        this.state.isLoading = true;
        const overlay = document.getElementById('loading-overlay');
        const loadingMessage = document.getElementById('loading-message');
        if (overlay) {
            overlay.classList.remove('hidden');
        }
        if (loadingMessage) {
            loadingMessage.textContent = message;
        }
    }

    /**
     * Hide loading overlay
     */
    hideLoading() {
        this.state.isLoading = false;
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.add('hidden');
        }
    }

    /**
     * Show success message
     */
    showSuccess(message) {
        this.showMessage(message, 'success');
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showMessage(message, 'error');
    }

    /**
     * Show warning message
     */
    showWarning(message) {
        this.showMessage(message, 'warning');
    }

    /**
     * Show status message
     */
    showMessage(message, type = 'info') {
        const statusEl = document.getElementById('status-message');
        if (!statusEl) return;

        statusEl.textContent = message;
        statusEl.className = `status-message ${type}`;
        statusEl.classList.remove('hidden');

        // Auto-hide after 5 seconds
        setTimeout(() => {
            statusEl.classList.add('hidden');
        }, 5000);
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new WebAuthnApp();
});
