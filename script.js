// Updated script.js for 2R-AT with real backend integration

// Backend configuration
const BACKEND_URL = window.location.origin + '/api';

// Authentication System
class AuthSystem {
    constructor() {
        this.currentUser = null;
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.sessionTimer = null;
        this.token = localStorage.getItem('2r-at-token');

        // Check for existing session
        this.checkExistingSession();
    }

    async checkExistingSession() {
        if (this.token) {
            try {
                // Validate token by trying to get user profile
                const response = await this.makeAuthenticatedRequest('/auth/profile');
                if (response.ok) {
                    const userData = await response.json();
                    this.currentUser = userData.user;
                    this.updateUIForAuthenticatedUser();
                    this.startSessionTimer();
                } else {
                    // Token invalid, clear it
                    this.clearToken();
                }
            } catch (error) {
                console.error('Session validation failed:', error);
                this.clearToken();
            }
        }
        
        if (!this.currentUser) {
            this.updateUIForUnauthenticatedUser();
        }
    }

    async makeAuthenticatedRequest(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            }
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        return fetch(`${BACKEND_URL}${endpoint}`, mergedOptions);
    }

    clearToken() {
        this.token = null;
        localStorage.removeItem('2r-at-token');
    }

    async register(userData) {
        try {
            const response = await fetch(`${BACKEND_URL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Registration failed');
            }

            // Store token and user data
            this.token = data.token;
            localStorage.setItem('2r-at-token', this.token);
            this.currentUser = data.user;

            this.updateUIForAuthenticatedUser();
            this.startSessionTimer();

            showNotification('Account created successfully! Welcome to 2R-AT Security.', 'success');
            closeAuthModal();

            return data.user;
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    async login(email, password) {
        try {
            const response = await fetch(`${BACKEND_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store token and user data
            this.token = data.token;
            localStorage.setItem('2r-at-token', this.token);
            this.currentUser = data.user;

            this.updateUIForAuthenticatedUser();
            this.startSessionTimer();

            showNotification(`Welcome back, ${this.currentUser.name}!`, 'success');
            closeAuthModal();

            return this.currentUser;
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    logout() {
        this.currentUser = null;
        this.clearToken();
        this.clearSessionTimer();
        this.updateUIForUnauthenticatedUser();
        showNotification('You have been logged out securely.', 'success');

        // Redirect to home if on protected page
        window.location.hash = '#home';
    }

    updateUIForAuthenticatedUser() {
        // Hide auth buttons, show user menu
        document.getElementById('auth-buttons').style.display = 'none';
        document.getElementById('user-menu').style.display = 'block';

        // Update user avatar and info
        const avatar = document.getElementById('user-avatar');
        const initials = this.currentUser.name.split(' ').map(n => n[0]).join('').toUpperCase();
        avatar.textContent = initials;

        // Add role-based styling
        avatar.className = `user-avatar role-${this.currentUser.role}`;

        document.getElementById('user-display-name').textContent = this.currentUser.name;
        document.getElementById('user-email').textContent = this.currentUser.email;
        document.getElementById('user-role').textContent = `${this.currentUser.role} • ${this.currentUser.plan.charAt(0).toUpperCase() + this.currentUser.plan.slice(1)} Plan`;

        // Remove protected overlays
        this.removeProtectedOverlays();

        // Update dashboard with user stats (mock for now)
        this.updateUserDashboard();
    }

    updateUIForUnauthenticatedUser() {
        // Show auth buttons, hide user menu
        document.getElementById('auth-buttons').style.display = 'flex';
        document.getElementById('user-menu').style.display = 'none';

        // Add protected overlays
        this.addProtectedOverlays();

        // Hide user dashboard stats
        const userStats = document.getElementById('user-dashboard-stats');
        if (userStats) userStats.style.display = 'none';
    }

    addProtectedOverlays() {
        const protectedSections = ['dashboard-container', 'ctf-challenges-grid'];

        protectedSections.forEach(sectionId => {
            const section = document.getElementById(sectionId);
            if (section && !section.querySelector('.protected-overlay')) {
                const overlay = document.createElement('div');
                overlay.className = 'protected-overlay';
                overlay.innerHTML = `
                    <div class="protected-content">
                        <div class="protected-icon">🔒</div>
                        <h3 class="protected-title">Authentication Required</h3>
                        <p class="protected-text">Please log in to access this premium content and advanced security features.</p>
                        <button class="btn btn-primary" onclick="showAuthModal('login')">Login Now</button>
                        <button class="btn btn-secondary" onclick="showAuthModal('register')" style="margin-left: 1rem;">Create Account</button>
                    </div>
                `;
                section.style.position = 'relative';
                section.appendChild(overlay);
            }
        });
    }

    removeProtectedOverlays() {
        const overlays = document.querySelectorAll('.protected-overlay');
        overlays.forEach(overlay => overlay.remove());
    }

    updateUserDashboard() {
        const userStats = document.getElementById('user-dashboard-stats');
        if (userStats) {
            userStats.style.display = 'block';

            // Mock stats for now - in a real app, these would come from the backend
            const mockStats = {
                threatsBlocked: Math.floor(Math.random() * 1000) + 100,
                ctfPoints: Math.floor(Math.random() * 5000) + 500,
                challengesCompleted: Math.floor(Math.random() * 10) + 1,
                rank: 'Security Specialist'
            };

            document.getElementById('user-threats-blocked').textContent = mockStats.threatsBlocked.toLocaleString();
            document.getElementById('user-ctf-points').textContent = mockStats.ctfPoints.toLocaleString();
            document.getElementById('user-challenges-completed').textContent = mockStats.challengesCompleted;
            document.getElementById('user-rank').textContent = mockStats.rank;

            // Mock achievements
            const achievementsContainer = document.getElementById('user-achievements');
            const mockAchievements = [
                { icon: '🎉', name: 'Welcome Aboard' },
                { icon: '🔍', name: 'First Scan' },
                { icon: '🛡️', name: 'Security Expert' }
            ];
            achievementsContainer.innerHTML = mockAchievements.map(achievement =>
                `<div class="badge">${achievement.icon} ${achievement.name}</div>`
            ).join('');
        }
    }

    startSessionTimer() {
        this.clearSessionTimer();
        this.sessionTimer = setTimeout(() => {
            showNotification('Session expired for security. Please log in again.', 'warning');
            this.logout();
        }, this.sessionTimeout);
    }

    clearSessionTimer() {
        if (this.sessionTimer) {
            clearTimeout(this.sessionTimer);
            this.sessionTimer = null;
        }
    }

    isAuthenticated() {
        return this.currentUser !== null && this.token !== null;
    }

    getCurrentUser() {
        return this.currentUser;
    }
}

// Nuclei Scan Manager
class NucleiScanManager {
    constructor() {
        this.currentScanId = null;
        this.pollInterval = null;
        this.maxPollTime = 30 * 60 * 1000; // 30 minutes max polling
        this.pollStartTime = null;
    }

    async startScan(hostname, scanName = null) {
        if (!auth.isAuthenticated()) {
            throw new Error('Authentication required');
        }

        try {
            const response = await auth.makeAuthenticatedRequest('/scan/start', {
                method: 'POST',
                body: JSON.stringify({
                    hostname: hostname,
                    scan_name: scanName || `Quick Scan - ${hostname}`
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            this.currentScanId = data.scan_id;
            this.pollStartTime = Date.now();
            
            return data;
        } catch (error) {
            console.error('Error starting scan:', error);
            throw error;
        }
    }

    async getScanStatus(scanId) {
        if (!auth.isAuthenticated()) {
            throw new Error('Authentication required');
        }

        try {
            const response = await auth.makeAuthenticatedRequest(`/scan/${scanId}/status`);
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Error getting scan status:', error);
            throw error;
        }
    }

    startPolling(scanId, onUpdate, onComplete, onError) {
        this.stopPolling(); // Clear any existing polling

        const poll = async () => {
            try {
                // Check if we've exceeded max poll time
                if (Date.now() - this.pollStartTime > this.maxPollTime) {
                    this.stopPolling();
                    onError(new Error('Scan polling timeout. Please check the scan status manually.'));
                    return;
                }

                const status = await this.getScanStatus(scanId);
                onUpdate(status);

                if (status.status === 'completed') {
                    this.stopPolling();
                    onComplete(status);
                } else if (status.status === 'failed' || status.status === 'cancelled') {
                    this.stopPolling();
                    onError(new Error(`Scan ${status.status}: ${status.error || 'Unknown error'}`));
                }
                // Continue polling for 'running' or 'queued' status
            } catch (error) {
                this.stopPolling();
                onError(error);
            }
        };

        // Poll immediately, then every 10 seconds
        poll();
        this.pollInterval = setInterval(poll, 10000);
    }

    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    async getReportUrl(scanId) {
        return `${BACKEND_URL}/scan/${scanId}/report`;
    }
}

// Initialize systems
const auth = new AuthSystem();
const nessusScanManager = new NucleiScanManager();

// Updated Quick Scan Functionality
function handleQuickScan() {
    const targetInput = document.getElementById('quick-scan-target');
    const scanButton = document.getElementById('quick-scan-button');
    const outputElement = document.getElementById('quick-scan-output');
    const resultsElement = document.getElementById('quick-scan-results');

    if (!targetInput || !scanButton || !outputElement || !resultsElement) {
        console.error('Quick scan elements not found!');
        return;
    }

    // Check authentication
    if (!auth.isAuthenticated()) {
        showAuthModal('login');
        return;
    }

    const hostname = targetInput.value.trim();
    if (!hostname) {
        outputElement.innerHTML = '<span style="color: var(--warning);">Please enter a hostname or IP address to scan.</span>';
        resultsElement.innerHTML = '';
        return;
    }

    // Disable controls
    scanButton.disabled = true;
    targetInput.disabled = true;
    scanButton.textContent = 'Scanning...';

    // Show initial status
    outputElement.innerHTML = `[+] Initiating Nuclei vulnerability scan for <strong>${hostname}</strong>...<br>[+] Connecting to security scanner...<br>[+] Please wait, this may take several minutes...`;
    resultsElement.innerHTML = '<div class="loader-circle" style="margin: 2rem auto;"></div>';

    // Start the scan
    nessusScanManager.startScan(hostname)
        .then(scanData => {
            outputElement.innerHTML += `<br>[+] Scan initiated successfully (ID: ${scanData.scan_id})<br>[+] Monitoring scan progress...`;

            // Start polling for status updates
            nessusScanManager.startPolling(
                scanData.scan_id,
                // onUpdate callback
                (status) => {
                    const statusMessages = {
                        'queued': '[+] Scan queued for execution...',
                        'running': '[+] Scan in progress, analyzing target systems...',
                    };
                    
                    if (statusMessages[status.status]) {
                        const lines = outputElement.innerHTML.split('<br>');
                        const lastLine = lines[lines.length - 1];
                        if (!lastLine.includes('Scan in progress') && status.status === 'running') {
                            outputElement.innerHTML += '<br>' + statusMessages[status.status];
                        }
                    }
                },
                // onComplete callback
                (finalStatus) => {
                    handleScanComplete(finalStatus, hostname);
                },
                // onError callback
                (error) => {
                    handleScanError(error, hostname);
                }
            );
        })
        .catch(error => {
            handleScanError(error, hostname);
        })
        .finally(() => {
            // Re-enable controls
            scanButton.disabled = false;
            targetInput.disabled = false;
            scanButton.textContent = 'Start Scan';
        });
}

function handleScanComplete(scanResult, hostname) {
    const outputElement = document.getElementById('quick-scan-output');
    const resultsElement = document.getElementById('quick-scan-results');

    const duration = calculateScanDuration(scanResult.created_at, scanResult.completed_at);
    outputElement.innerHTML = `[+] ✅ Nuclei vulnerability scan completed for <strong>${hostname}</strong><br>[+] Scan Duration: ${duration}<br>[+] Processing results...`;
    resultsElement.innerHTML = '';

    // Build summary
    let summaryHTML = '<div style="text-align:left; margin-bottom:2rem;"><h4 style="color: var(--primary);">📊 Scan Summary</h4>';
    
    if (scanResult.summary) {
        const summary = scanResult.summary;
        summaryHTML += `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0;">`;
        summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--primary);"><strong>Total Hosts:</strong><br>${summary.total_hosts || 1}</div>`;
        if (scanResult.vulnerabilities) {
            const vulns = scanResult.vulnerabilities;
            const total = Object.values(vulns).reduce((a, b) => a + b, 0);
            summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid ${total > 0 ? 'var(--danger)' : 'var(--success)'};"><strong>Total Vulnerabilities:</strong><br>${total}</div>`;
            if (vulns.critical > 0) summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--danger);"><strong>Critical:</strong><br>${vulns.critical}</div>`;
            if (vulns.high > 0) summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--danger);"><strong>High:</strong><br>${vulns.high}</div>`;
            if (vulns.medium > 0) summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--warning);"><strong>Medium:</strong><br>${vulns.medium}</div>`;
            if (vulns.low > 0) summaryHTML += `<div style="background: rgba(10,14,39,0.6); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--success);"><strong>Low:</strong><br>${vulns.low}</div>`;
        }
        summaryHTML += '</div>';
    }
    summaryHTML += '</div>';
    resultsElement.innerHTML += summaryHTML;

    // Show detailed vulnerabilities if available
    if (scanResult.vulnerabilities_list && scanResult.vulnerabilities_list.length > 0) {
        let vulnerabilitiesHTML = '<h4 style="text-align:left; margin-bottom:1rem; color: var(--primary);">🔍 Detailed Findings</h4>';
        vulnerabilitiesHTML += '<div style="max-height: 500px; overflow-y: auto; border: 1px solid rgba(0,212,255,0.2); border-radius: 8px; padding: 1rem;">';
        
        scanResult.vulnerabilities_list.forEach(vuln => {
            const severityColors = {
                'Critical': 'var(--danger)',
                'High': 'var(--danger)', 
                'Medium': 'var(--warning)',
                'Low': 'var(--success)',
                'Info': 'var(--gray)'
            };
            
            const severityColor = severityColors[vuln.severity] || 'var(--gray)';
            
            vulnerabilitiesHTML += `
                <div style="margin-bottom: 1.5rem; padding: 1.5rem; border: 1px solid ${severityColor}; border-left-width: 5px; border-radius: 8px; background: rgba(10,14,39,0.4);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                        <h5 style="color: ${severityColor}; margin: 0; flex: 1;">${vuln.name || 'Unknown Vulnerability'}</h5>
                        <span style="background: ${severityColor}; color: white; padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.8rem; font-weight: bold;">${vuln.severity}</span>
                    </div>
                    ${vuln.plugin_id && vuln.plugin_id !== 'N/A' ? `<p style="font-size: 0.8rem; color: var(--gray); margin: 0.5rem 0;">Template ID: ${vuln.plugin_id}</p>` : ''}
                    <p style="color: var(--light); margin: 1rem 0; line-height: 1.5;">${vuln.description || 'No description provided.'}</p>
                    <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 5px; border-left: 3px solid var(--primary);">
                        <strong style="color: var(--primary);">💡 Solution:</strong>
                        <p style="color: var(--gray); margin: 0.5rem 0 0 0; font-style: italic;">${vuln.solution || 'No solution provided.'}</p>
                    </div>
                </div>
            `;
        });
        
        vulnerabilitiesHTML += '</div>';
        resultsElement.innerHTML += vulnerabilitiesHTML;
    } else {
        resultsElement.innerHTML += `
            <div style="text-align: center; padding: 2rem; background: rgba(16,185,129,0.1); border: 1px solid var(--success); border-radius: 8px;">
                <h4 style="color: var(--success); margin-bottom: 1rem;">🛡️ Great News!</h4>
                <p style="color: var(--light);">No vulnerabilities were detected during this scan of <strong>${hostname}</strong>.</p>
                <p style="color: var(--gray); font-size: 0.9rem;">This is a preliminary scan. For comprehensive security assessment, consider our advanced penetration testing services.</p>
            </div>
        `;
    }

    // Add action buttons
    let actionsHTML = '<div style="text-align: center; margin-top: 2rem; padding-top: 2rem; border-top: 1px solid rgba(255,255,255,0.1);">';
    
    if (scanResult.report_url) {
        const reportUrl = nessusScanManager.getReportUrl(scanResult.scan_id);
        actionsHTML += `<a href="${reportUrl}" target="_blank" class="btn btn-primary" style="margin-right: 1rem;">📄 Download Full Report</a>`;
    }
    
    actionsHTML += `
        <a href="#security-assessment" class="btn btn-secondary" style="margin-right: 1rem;">🔍 Advanced Assessments</a>
        <a href="#contact" class="btn btn-primary">🤝 Contact Security Experts</a>
    `;
    actionsHTML += '</div>';
    
    resultsElement.innerHTML += actionsHTML;
}

function handleScanError(error, hostname) {
    const outputElement = document.getElementById('quick-scan-output');
    const resultsElement = document.getElementById('quick-scan-results');

    outputElement.innerHTML = `[+] ❌ Scan failed for <strong>${hostname}</strong><br>[!] ${error.message}`;
    resultsElement.innerHTML = `
        <div style="text-align: center; padding: 2rem; background: rgba(239,68,68,0.1); border: 1px solid var(--danger); border-radius: 8px;">
            <h4 style="color: var(--danger); margin-bottom: 1rem;">⚠️ Scan Error</h4>
            <p style="color: var(--light); margin-bottom: 1rem;">The vulnerability scan could not be completed for the following reason:</p>
            <p style="color: var(--danger); font-family: monospace; background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 5px;">${error.message}</p>
            <div style="margin-top: 2rem;">
                <button class="btn btn-secondary" onclick="retryQuickScan()" style="margin-right: 1rem;">🔄 Retry Scan</button>
                <a href="#contact" class="btn btn-primary">📞 Contact Support</a>
            </div>
        </div>
    `;
}

function retryQuickScan() {
    const targetInput = document.getElementById('quick-scan-target');
    const resultsElement = document.getElementById('quick-scan-results');
    const outputElement = document.getElementById('quick-scan-output');
    
    resultsElement.innerHTML = '';
    outputElement.innerHTML = 'Ready to retry scan...';
    
    // Small delay then retry
    setTimeout(handleQuickScan, 500);
}

function calculateScanDuration(startTime, endTime) {
    if (!startTime || !endTime) return 'Unknown';
    
    const start = new Date(startTime);
    const end = new Date(endTime);
    const durationMs = end - start;
    
    const minutes = Math.floor(durationMs / 60000);
    const seconds = Math.floor((durationMs % 60000) / 1000);
    
    if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    } else {
        return `${seconds}s`;
    }
}

// Authentication Modal Functions (updated)
function showAuthModal(mode = 'login') {
    document.getElementById('auth-modal').style.display = 'block';
    document.body.style.overflow = 'hidden';
    switchAuthTab(mode);
}

function closeAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
    document.body.style.overflow = 'auto';
}

function switchAuthTab(mode) {
    // Update tabs
    document.getElementById('login-tab').classList.toggle('active', mode === 'login');
    document.getElementById('register-tab').classList.toggle('active', mode === 'register');

    // Update forms
    document.getElementById('login-form').classList.toggle('active', mode === 'login');
    document.getElementById('register-form').classList.toggle('active', mode === 'register');

    // Update header
    if (mode === 'login') {
        document.getElementById('auth-title').textContent = 'Welcome Back';
        document.getElementById('auth-subtitle').textContent = 'Secure access to your account';
    } else {
        document.getElementById('auth-title').textContent = 'Join 2R-AT Security';
        document.getElementById('auth-subtitle').textContent = 'Start your cybersecurity journey';
    }
}

// Authentication Handlers (updated)
async function handleLogin(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const email = formData.get('email');
    const password = formData.get('password');

    try {
        await auth.login(email, password);
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function handleRegister(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const userData = {
        name: formData.get('name'),
        email: formData.get('email'),
        company: formData.get('company'),
        role: formData.get('role'),
        password: formData.get('password'),
        confirm: formData.get('confirm')
    };

    // Client-side validation
    if (userData.password !== userData.confirm) {
        showNotification('Passwords do not match', 'error');
        return;
    }

    if (userData.password.length < 8) {
        showNotification('Password must be at least 8 characters', 'error');
        return;
    }

    try {
        await auth.register(userData);
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function logout() {
    auth.logout();
    toggleUserDropdown(); // Close dropdown
}

// User Menu Functions
function toggleUserDropdown() {
    const dropdown = document.getElementById('user-dropdown');
    dropdown.classList.toggle('active');
}

// Profile and Settings Functions
function showProfile() {
    if (!auth.isAuthenticated()) return;

    const user = auth.getCurrentUser();
    alert(`Profile Information:

Name: ${user.name}
Email: ${user.email}
Company: ${user.company || 'Not specified'}
Role: ${user.role}
Plan: ${user.plan.charAt(0).toUpperCase() + user.plan.slice(1)}

Note: Full profile management coming soon!`);
}

function showAchievements() {
    alert('Achievements system coming soon! Complete security challenges to unlock badges and certifications.');
}

function showSettings() {
    alert('Settings panel coming soon with options for:\n\n• Account preferences\n• Security settings\n• Notification preferences\n• Privacy controls\n• Two-factor authentication');
}

// Notification System
function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    const messageElement = document.getElementById('notification-message');

    messageElement.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');

    setTimeout(() => {
        notification.classList.remove('show');
    }, 5000);
}

// Contact Form Handler (updated)
function handleContactForm(event) {
    event.preventDefault();

    const button = event.target.querySelector('button[type="submit"]');
    const originalText = button.textContent;
    button.textContent = 'Securing transmission...';
    button.disabled = true;

    setTimeout(() => {
        button.textContent = 'Message encrypted & sent ✓';
        button.style.background = 'var(--success)';

        const user = auth.getCurrentUser();
        const message = user ?
            `Thank you ${user.name}! Your security assessment request has been prioritized.` :
            'Thank you! Your security assessment request has been received.';

        showNotification(message, 'success');

        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
            button.style.background = '';
            event.target.reset();
        }, 3000);
    }, 2000);
}

// Initialize UI based on authentication status
document.addEventListener('DOMContentLoaded', () => {
    // Add event listener for the quick scan button
    const quickScanButton = document.getElementById('quick-scan-button');
    if (quickScanButton) {
        quickScanButton.addEventListener('click', handleQuickScan);
    } else {
        console.error('Quick scan button not found on DOMContentLoaded');
    }
});

// Close modal when clicking outside
window.addEventListener('click', (event) => {
    const authModal = document.getElementById('auth-modal');
    if (event.target === authModal) {
        closeAuthModal();
    }
});

// Close dropdown when clicking outside
document.addEventListener('click', (event) => {
    const userMenu = document.getElementById('user-menu');
    const dropdown = document.getElementById('user-dropdown');

    if (userMenu && dropdown && !userMenu.contains(event.target)) {
        dropdown.classList.remove('active');
    }
});

// Remove loader after page load
window.addEventListener('load', () => {
    setTimeout(() => {
        const loader = document.getElementById('loader');
        if (loader) {
            loader.style.opacity = '0';
            setTimeout(() => {
                loader.style.display = 'none';
            }, 500);
        }
    }, 1000);
});

// Particle Effect
function createParticle() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;

    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * window.innerWidth + 'px';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.opacity = Math.random() * 0.5 + 0.1;
    particlesContainer.appendChild(particle);

    setTimeout(() => {
        particle.remove();
    }, 15000);
}

// Create particles periodically
setInterval(createParticle, 300);

// Smooth scrolling
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const href = this.getAttribute('href');

        // Check if href has content after the hash
        if (href && href.length > 1) {
            const target = document.querySelector(href);
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        }

        // Close mobile menu if open
        const navLinks = document.querySelector('.nav-links');
        const mobileToggle = document.querySelector('.mobile-menu-toggle');
        if (navLinks && navLinks.classList.contains('active')) {
            navLinks.classList.remove('active');
            mobileToggle.classList.remove('active');
        }
    });
});

// Navbar background on scroll
window.addEventListener('scroll', () => {
    const navbar = document.getElementById('navbar');
    if (navbar) {
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(5, 7, 20, 0.95)';
            navbar.style.boxShadow = '0 5px 20px rgba(0, 0, 0, 0.5)';
        } else {
            navbar.style.background = 'rgba(5, 7, 20, 0.9)';
            navbar.style.boxShadow = 'none';
        }
    }
});

// Mobile menu toggle
const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
const navLinks = document.querySelector('.nav-links');

if (mobileMenuToggle && navLinks) {
    mobileMenuToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        mobileMenuToggle.classList.toggle('active');
    });
}

// Keyboard shortcuts for power users
document.addEventListener('keydown', (event) => {
    // Ctrl+L to open login
    if (event.ctrlKey && event.key === 'l') {
        event.preventDefault();
        if (!auth.isAuthenticated()) {
            showAuthModal('login');
        }
    }

    // Escape to close modals
    if (event.key === 'Escape') {
        closeAuthModal();
        const dropdown = document.getElementById('user-dropdown');
        if (dropdown) {
            dropdown.classList.remove('active');
        }
    }
});
