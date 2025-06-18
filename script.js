const mockVulnerabilities = [
    {
        id: 'CVE-SIM-001',
        name: 'Simulated SQL Injection Vulnerability',
        description: 'A simulated vulnerability allowing potential unauthorized database access due to improperly sanitized user inputs on login forms or search parameters.',
        severity: 'High',
        keywords: ['sql', 'database', 'login', 'injection', 'sqli', 'auth'],
        solution_hint: 'Implement parameterized queries or prepared statements. Sanitize all user inputs rigorously. Use a Web Application Firewall (WAF).'
    },
    {
        id: 'CVE-SIM-002',
        name: 'Simulated Cross-Site Scripting (XSS)',
        description: 'A simulated vulnerability where malicious scripts could be injected into web pages viewed by other users, potentially leading to session hijacking or data theft.',
        severity: 'Medium',
        keywords: ['xss', 'scripting', 'cross-site', 'html', 'injection', 'cookie'],
        solution_hint: 'Implement strong Content Security Policy (CSP). Encode output data correctly (e.g., HTML entity encoding). Validate and sanitize user inputs.'
    },
    {
        id: 'CVE-SIM-003',
        name: 'Outdated Web Server Software Detected',
        description: 'The target appears to be running an outdated version of a web server software (e.g., Apache, Nginx), which may have known vulnerabilities.',
        severity: 'Medium',
        keywords: ['server', 'apache', 'nginx', 'iis', 'version', 'cve', 'exploit', 'patch'],
        solution_hint: 'Regularly update server software to the latest stable versions. Apply security patches promptly. Subscribe to vendor security advisories.'
    },
    {
        id: 'CVE-SIM-004',
        name: 'Missing Security Headers',
        description: 'Important HTTP security headers (e.g., Strict-Transport-Security, Content-Security-Policy, X-Frame-Options) are not implemented or misconfigured.',
        severity: 'Low',
        keywords: ['header', 'hsts', 'csp', 'x-frame-options', 'security policy', 'http'],
        solution_hint: 'Configure your web server to send appropriate security headers. Use tools like securityheaders.com to check your configuration.'
    },
    {
        id: 'CVE-SIM-005',
        name: 'Weak SSL/TLS Configuration',
        description: 'The SSL/TLS configuration uses weak ciphers, outdated protocols (e.g., SSLv3, TLS 1.0/1.1), or has certificate issues.',
        severity: 'Medium',
        keywords: ['ssl', 'tls', 'cipher', 'protocol', 'certificate', 'encryption', 'https'],
        solution_hint: 'Configure your server to support only strong cipher suites and modern TLS versions (TLS 1.2, TLS 1.3). Ensure your SSL certificate is valid and properly installed.'
    },
    {
        id: 'CVE-SIM-006',
        name: 'Exposed Admin Interface',
        description: 'An administrative interface or login panel seems to be publicly accessible, increasing the risk of brute-force attacks or unauthorized access attempts.',
        severity: 'High',
        keywords: ['admin', 'login', 'panel', 'wp-admin', 'administrator', 'auth', 'brute force'],
        solution_hint: 'Restrict access to admin interfaces by IP address. Implement strong MFA. Use non-default paths for admin panels. Monitor login attempts.'
    },
    {
        id: 'CVE-SIM-007',
        name: 'Directory Traversal Vulnerability',
        description: 'A simulated vulnerability that could allow an attacker to access restricted directories and files on the server by manipulating file path inputs.',
        severity: 'High',
        keywords: ['traversal', 'path', 'directory', 'file', '../', 'inclusion'],
        solution_hint: 'Sanitize all user-supplied file paths. Implement proper access controls. Use whitelisting for allowed paths.'
    },
    {
        id: 'CVE-SIM-008',
        name: 'Information Leakage via Server Headers',
        description: 'Server software versions or other sensitive information are exposed in HTTP response headers, potentially aiding attackers.',
        severity: 'Low',
        keywords: ['server', 'version', 'banner', 'leakage', 'information disclosure'],
        solution_hint: 'Configure your web server to minimize or remove version information from HTTP headers (e.g., Server, X-Powered-By).'
    }
];

const detailedScanSteps = [
    (target) => `$ 2R-AT --scan --target ${target} --profile quick --intensity low`,
    '[+] Initializing advanced heuristic analysis engine...',
    '[+] Connecting to global threat intelligence network...',
    '[+] Calibrating anomaly detection parameters...',
    '[+] Scanning common ports (80, 443, 8080)...',
    '[+] Analyzing HTTP headers for security misconfigurations...',
    '[+] Checking for known vulnerable software versions (simulated)...',
    '[+] Simulating basic SQL injection and XSS probes...',
    '[+] Assessing SSL/TLS certificate chain and configuration...',
    '[+] Looking for exposed administrative interfaces...',
    '[+] Verifying DNS records and MX server health...',
    '[+] Cross-referencing findings with mock vulnerability database...',
    '[+] Generating preliminary risk assessment matrix...',
    '[+] Compiling simulated findings and recommendations...'
];

// Backend configuration
const BACKEND_URL = 'https://2r-at.com/api';

// Authentication System
class AuthSystem {
    constructor() {
        this.users = new Map(); // In-memory user storage
        this.currentUser = null;
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.sessionTimer = null;

        // Initialize with some demo users
        this.initializeDemoUsers();

        // Check for existing session
        this.checkExistingSession();
    }

    initializeDemoUsers() {
        // Demo users for testing
        const demoUsers = [
            {
                id: 'demo-admin',
                name: 'Admin User',
                email: 'admin@2r-at.com',
                password: 'admin123',
                role: 'admin',
                company: '2R-AT Security',
                userRole: 'CISO',
                plan: 'enterprise',
                joinDate: '2024-01-15',
                stats: {
                    threatsBlocked: 1547,
                    ctfPoints: 8750,
                    challengesCompleted: 12,
                    rank: 'Elite Defender'
                },
                achievements: [
                    { id: 'first-login', name: 'Welcome Aboard', icon: '🎉' },
                    { id: 'ctf-master', name: 'CTF Master', icon: '🏆' },
                    { id: 'threat-hunter', name: 'Threat Hunter', icon: '🎯' },
                    { id: 'security-expert', name: 'Security Expert', icon: '🛡️' }
                ]
            },
            {
                id: 'demo-user',
                name: 'Test User',
                email: 'user@example.com',
                password: 'user123',
                role: 'user',
                company: 'Tech Corp',
                userRole: 'Security Analyst',
                plan: 'professional',
                joinDate: '2024-06-20',
                stats: {
                    threatsBlocked: 342,
                    ctfPoints: 2150,
                    challengesCompleted: 5,
                    rank: 'Security Specialist'
                },
                achievements: [
                    { id: 'first-login', name: 'Welcome Aboard', icon: '🎉' },
                    { id: 'first-challenge', name: 'First Challenge', icon: '🎯' }
                ]
            }
        ];

        demoUsers.forEach(user => {
            this.users.set(user.email, user);
        });

        // Debug: Log available users
        console.log('Demo users initialized:', Array.from(this.users.keys()));
    }

    checkExistingSession() {
        // In a real app, you'd check for a valid session token
        // For demo purposes, we'll keep users logged in during the session
        if (this.currentUser) {
            this.updateUIForAuthenticatedUser();
        }
    }

    async register(userData) {
        const { name, email, company, role, userRole, password, confirm } = userData;

        // Validation
        if (password !== confirm) {
            throw new Error('Passwords do not match');
        }

        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }

        if (this.users.has(email)) {
            throw new Error('Email already registered');
        }

        // Create new user
        const newUser = {
            id: 'user-' + Date.now(),
            name,
            email,
            company: company || 'Independent',
            role: 'user',
            userRole,
            password, // In real app, this would be hashed
            plan: 'basic',
            joinDate: new Date().toISOString().split('T')[0],
            stats: {
                threatsBlocked: 0,
                ctfPoints: 0,
                challengesCompleted: 0,
                rank: 'Novice'
            },
            achievements: [
                { id: 'first-login', name: 'Welcome Aboard', icon: '🎉' }
            ]
        };

        this.users.set(email, newUser);

        // Auto-login after registration
        this.currentUser = newUser;
        this.updateUIForAuthenticatedUser();
        this.startSessionTimer();

        showNotification('Account created successfully! Welcome to 2R-AT Security.', 'success');
        closeAuthModal();

        return newUser;
    }

    async login(email, password) {
        console.log('Login attempt:', email, password);
        console.log('Available users:', Array.from(this.users.keys()));

        const user = this.users.get(email);
        console.log('Found user:', user);

        if (!user || user.password !== password) {
            console.log('Login failed - Invalid credentials');
            throw new Error('Invalid email or password');
        }

        this.currentUser = user;
        this.updateUIForAuthenticatedUser();
        this.startSessionTimer();

        showNotification(`Welcome back, ${user.name}!`, 'success');
        closeAuthModal();

        console.log('Login successful for:', user.name);
        return user;
    }

    logout() {
        this.currentUser = null;
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
        document.getElementById('user-role').textContent = `${this.currentUser.userRole} • ${this.currentUser.plan.charAt(0).toUpperCase() + this.currentUser.plan.slice(1)} Plan`;

        // Remove protected overlays
        this.removeProtectedOverlays();

        // Update dashboard with user stats
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

            // Update stats
            document.getElementById('user-threats-blocked').textContent = this.currentUser.stats.threatsBlocked.toLocaleString();
            document.getElementById('user-ctf-points').textContent = this.currentUser.stats.ctfPoints.toLocaleString();
            document.getElementById('user-challenges-completed').textContent = this.currentUser.stats.challengesCompleted;
            document.getElementById('user-rank').textContent = this.currentUser.stats.rank;

            // Update achievements
            const achievementsContainer = document.getElementById('user-achievements');
            achievementsContainer.innerHTML = this.currentUser.achievements.map(achievement =>
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
        return this.currentUser !== null;
    }

    getCurrentUser() {
        return this.currentUser;
    }

    updateUserStats(statType, value) {
        if (this.currentUser) {
            this.currentUser.stats[statType] += value;
            this.updateUserDashboard();

            // Update user in storage
            this.users.set(this.currentUser.email, this.currentUser);
        }
    }

    addAchievement(achievementId, name, icon) {
        if (this.currentUser) {
            const existing = this.currentUser.achievements.find(a => a.id === achievementId);
            if (!existing) {
                this.currentUser.achievements.push({ id: achievementId, name, icon });
                this.updateUserDashboard();
                showNotification(`🎉 Achievement Unlocked: ${name}!`, 'success');
            }
        }
    }
}

// Initialize authentication system
const auth = new AuthSystem();

// Nessus Scan Integration
class NessusScanManager {
    constructor() {
        this.currentScanId = null;
        this.pollInterval = null;
        this.maxPollTime = 30 * 60 * 1000; // 30 minutes max polling
        this.pollStartTime = null;
    }

    async startScan(hostname, scanName = null) {
        try {
            const response = await fetch(`${BACKEND_URL}/scan/start`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hostname: hostname,
                    scan_name: scanName || `Quick Scan - ${hostname}`,
                    email_notification: auth.isAuthenticated() ? auth.getCurrentUser().email : null
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
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
        try {
            const response = await fetch(`${BACKEND_URL}/scan/${scanId}/status`);
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
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

// Initialize Nessus scan manager
const nessusScanManager = new NessusScanManager();

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

    const hostname = targetInput.value.trim();
    if (!hostname) {
        outputElement.innerHTML = '<span style="color: var(--warning);">Please enter a hostname or IP address to scan.</span>';
        resultsElement.innerHTML = '';
        return;
    }

    // Validate hostname format (basic validation)
    const hostnameRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!hostnameRegex.test(hostname)) {
        outputElement.innerHTML = '<span style="color: var(--danger);">Please enter a valid hostname or IP address.</span>';
        resultsElement.innerHTML = '';
        return;
    }

    // Disable controls
    scanButton.disabled = true;
    targetInput.disabled = true;
    scanButton.textContent = 'Scanning...';

    // Show initial status
    outputElement.innerHTML = `[+] Initiating Nessus vulnerability scan for <strong>${hostname}</strong>...<br>[+] Connecting to Nessus server at 10.1.97.10...<br>[+] Please wait, this may take several minutes...`;
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

    outputElement.innerHTML = `[+] ✅ Nessus vulnerability scan completed for <strong>${hostname}</strong><br>[+] Scan Duration: ${calculateScanDuration(scanResult.created_at, scanResult.completed_at)}<br>[+] Processing results...`;
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
                    ${vuln.plugin_id && vuln.plugin_id !== 'N/A' ? `<p style="font-size: 0.8rem; color: var(--gray); margin: 0.5rem 0;">Plugin ID: ${vuln.plugin_id}</p>` : ''}
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
        actionsHTML += `<a href="${BACKEND_URL}${scanResult.report_url}" target="_blank" class="btn btn-primary" style="margin-right: 1rem;">📄 Download Full Report</a>`;
    }
    
    actionsHTML += `
        <a href="#security-assessment" class="btn btn-secondary" style="margin-right: 1rem;">🔍 Advanced Assessments</a>
        <a href="#contact" class="btn btn-primary">🤝 Contact Security Experts</a>
    `;
    actionsHTML += '</div>';
    
    resultsElement.innerHTML += actionsHTML;

    // Update user stats if authenticated
    if (auth.isAuthenticated()) {
        auth.updateUserStats('threatsBlocked', scanResult.vulnerabilities_list ? scanResult.vulnerabilities_list.length : 0);
        auth.addAchievement('first-scan', 'First Vulnerability Scan', '🔍');
    }
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

// CTF Challenge System
const ctfChallenges = {
    'web-app': {
        title: 'Corporate Data Breach Investigation',
        correctFlag: '2R-AT{SQL_1nj3ct10n_4nd_XSS_c0mb0_4tt4ck}',
        points: 1000,
        hints: [
            { text: "Look for SQL injection in the login form - try using single quotes", cost: 50 },
            { text: "The admin panel might have XSS vulnerabilities in the search function", cost: 100 },
            { text: "Check the source code for hidden admin credentials in JavaScript comments", cost: 150 }
        ]
    },
    'network-forensics': {
        title: 'APT Network Infiltration Analysis',
        correctFlag: '2R-AT{C2_53rv3r_192.168.100.42_p0rt_8080_DN5_tunneling}',
        points: 800,
        hints: [
            { text: "Focus on DNS queries that look like base64 encoded data", cost: 40 },
            { text: "The C2 server uses port 8080 and disguises traffic as HTTP requests", cost: 80 },
            { text: "Look for packets with unusual user-agent strings containing 'APT-Agent-v2.1'", cost: 120 }
        ]
    },
    'cryptography': {
        title: 'State-Sponsored Crypto Espionage',
        correctFlag: '2R-AT{SILVER_STORM_2025_power_grid_attack_feb_15}',
        points: 600,
        hints: [
            { text: "The first part is Base64 encoded, the second part uses ROT13 cipher", cost: 30 },
            { text: "Look for the operation codename in the decrypted message", cost: 60 },
            { text: "Combine the decrypted attack details with the operation codename", cost: 90 }
        ]
    },
    'digital-forensics': {
        title: 'Insider Threat Investigation',
        correctFlag: '2R-AT{john_smith_usb_exfiltration_2025-01-20_encrypted_7zip}',
        points: 1200,
        hints: [
            { text: "Check the Windows Event Logs for USB device insertion events", cost: 60 },
            { text: "Look for large 7zip files in the user's temp directory and recycle bin", cost: 120 },
            { text: "The suspect's name is in the laptop's user profile, combine with exfiltration method", cost: 180 }
        ]
    },
    'web-login-bypass': {
        title: 'Admin Portal Bypass',
        correctFlag: '2R-AT{admin_bypass_weak_client_validation_js}',
        points: 750,
        hints: [
            { text: "Look for client-side validation that can be bypassed", cost: 30 },
            { text: "Check if the authentication logic is implemented in JavaScript", cost: 70 },
            { text: "Try disabling JavaScript or modifying the validation function", cost: 100 }
        ]
    },
    'crypto-ancient-cipher': {
        title: 'Ancient Message Decryption',
        correctFlag: '2R-AT{crypt0_c43s4r_sh1ft_k3y15}',
        points: 550,
        hints: [
            { text: "This is a classical substitution cipher, very old but simple", cost: 20 },
            { text: "Julius Caesar used this cipher to communicate with his generals", cost: 50 },
            { text: "Try different shift values, the key might be 15", cost: 80 }
        ]
    }
};

const ctfPrizes = {
    1000: { rank: "🏆 EXPERT LEVEL", bonus: "You've earned a $500 Amazon gift card + priority consideration for our red team!", bg: "linear-gradient(135deg, #FFD700, #FFA500)" },
    800: { rank: "🥈 ADVANCED LEVEL", bonus: "You've earned a $300 Amazon gift card + access to our advanced training!", bg: "linear-gradient(135deg, #C0C0C0, #A0A0A0)" },
    600: { rank: "🥉 INTERMEDIATE LEVEL", bonus: "You've earned a $200 Amazon gift card + free certification voucher!", bg: "linear-gradient(135deg, #CD7F32, #B8860B)" },
    400: { rank: "🎯 BEGINNER LEVEL", bonus: "You've earned a $100 Amazon gift card + training course access!", bg: "linear-gradient(135deg, #32CD32, #228B22)" }
};

let userPoints = 0;
let usedHints = {};

// Authentication Modal Functions
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

// Authentication Handlers
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
        userRole: formData.get('role'),
        password: formData.get('password'),
        confirm: formData.get('confirm')
    };

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

// Protected Content Access Check
function checkAuth(section) {
    if (!auth.isAuthenticated()) {
        showNotification('Please log in to access this section.', 'warning');
        showAuthModal('login');
        return false;
    }
    return true;
}

// Profile and Settings Functions
function showProfile() {
    if (!auth.isAuthenticated()) return;

    const user = auth.getCurrentUser();
    alert(`Profile Information:

Name: ${user.name}
Email: ${user.email}
Company: ${user.company}
Role: ${user.userRole}
Plan: ${user.plan.charAt(0).toUpperCase() + user.plan.slice(1)}
Member Since: ${user.joinDate}

CTF Points: ${user.stats.ctfPoints}
Challenges Completed: ${user.stats.challengesCompleted}
Current Rank: ${user.stats.rank}`);
}

function showAchievements() {
    if (!auth.isAuthenticated()) return;

    const user = auth.getCurrentUser();
    const achievementsList = user.achievements.map(a => `${a.icon} ${a.name}`).join('\n');

    alert(`Your Achievements (${user.achievements.length}):

${achievementsList}

Keep completing challenges to unlock more achievements!`);
}

function showSettings() {
    alert('Settings panel would open here with options for:\n\n• Account preferences\n• Security settings\n• Notification preferences\n• Privacy controls\n• Two-factor authentication');
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

// CTF Functions
function showHint(challengeId, hintNumber) {
    if (!auth.isAuthenticated()) {
        showAuthModal('login');
        return;
    }

    const challenge = ctfChallenges[challengeId];
    const hint = challenge.hints[hintNumber - 1];

    if (!usedHints[challengeId]) {
        usedHints[challengeId] = [];
    }

    if (usedHints[challengeId].includes(hintNumber)) {
        alert("You've already used this hint!");
        return;
    }

    const useHint = confirm(`This hint will cost you ${hint.cost} points. Continue?\n\nHint: ${hint.text}`);
    if (useHint) {
        usedHints[challengeId].push(hintNumber);
        alert(`Hint revealed! You lost ${hint.cost} points.`);
    }
}

function submitFlag(challengeId) {
    if (!auth.isAuthenticated()) {
        showAuthModal('login');
        return;
    }

    const inputElement = document.getElementById(`flag-${challengeId}`);
    const submittedFlag = inputElement.value.trim();
    const challenge = ctfChallenges[challengeId];

    if (!submittedFlag) {
        alert("Please enter a flag!");
        return;
    }

    // Calculate points (deduct hint costs)
    let finalPoints = challenge.points;
    if (usedHints[challengeId]) {
        usedHints[challengeId].forEach(hintNum => {
            finalPoints -= challenge.hints[hintNum - 1].cost;
        });
    }

    if (submittedFlag === challenge.correctFlag) {
        // Correct flag submitted
        userPoints += finalPoints;
        auth.updateUserStats('ctfPoints', finalPoints);
        auth.updateUserStats('challengesCompleted', 1);
        showSuccessResponse(challengeId, finalPoints, challenge.title);
        inputElement.value = '';
        inputElement.disabled = true;

        // Add to recent submissions
        addToRecentSubmissions(challenge.title, finalPoints);

        // Show celebration
        createCelebrationEffect();

        // Add achievement
        if (finalPoints >= 1000) {
            auth.addAchievement('expert-solver', 'Expert Challenge Solver', '🎯');
        }
    } else {
        // Wrong flag
        showFailureResponse(submittedFlag, challengeId);
    }
}

function showSuccessResponse(challengeId, points, challengeTitle) {
    const resultsSection = document.getElementById('your-results');
    const resultContent = document.getElementById('result-content');

    // Determine prize level
    let prizeInfo = ctfPrizes[400]; // Default
    if (points >= 1000) prizeInfo = ctfPrizes[1000];
    else if (points >= 800) prizeInfo = ctfPrizes[800];
    else if (points >= 600) prizeInfo = ctfPrizes[600];

    resultContent.innerHTML = `
        <h4>🎊 FLAG CAPTURED SUCCESSFULLY! 🎊</h4>
        <div class="result-details">
            <div class="result-detail">
                <div class="label">Challenge</div>
                <div class="value">${challengeTitle}</div>
            </div>
            <div class="result-detail">
                <div class="label">Points Earned</div>
                <div class="value">+${points}</div>
            </div>
            <div class="result-detail">
                <div class="label">Total Points</div>
                <div class="value">${auth.getCurrentUser().stats.ctfPoints}</div>
            </div>
            <div class="result-detail">
                <div class="label">Achievement Level</div>
                <div class="value">${prizeInfo.rank}</div>
            </div>
        </div>
        <div style="background: ${prizeInfo.bg}; color: black; padding: 2rem; border-radius: 15px; margin-top: 2rem; font-weight: bold;">
            🎁 CONGRATULATIONS! ${prizeInfo.bonus}
            <br><br>
            📧 Prize details will be sent to your email within 24 hours.
            <br>
            📞 Our recruitment team may contact you for exciting career opportunities!
        </div>
        <div style="margin-top: 2rem;">
            <button class="btn btn-primary" onclick="shareSuccess('${challengeTitle}', ${points})">Share Your Achievement</button>
            <button class="btn btn-secondary" style="margin-left: 1rem;" onclick="downloadCertificate('${challengeTitle}')">Download Certificate</button>
        </div>
    `;

    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function showFailureResponse(submittedFlag, challengeId) {
    const responses = [
        "🚫 Incorrect flag! Keep analyzing the evidence...",
        "❌ Not quite right. Have you considered all the attack vectors?",
        "🔍 Close, but not correct. Review your methodology and try again.",
        "💭 Think like an attacker. What would be the most likely entry point?",
        "🎯 You're on the right track! Double-check your analysis.",
        "🧩 Every detail matters in cybersecurity. Look closer!",
        "⚡ Security is all about persistence. Don't give up!",
        "🔐 The answer is hidden in the details. Keep investigating!"
    ];

    const randomResponse = responses[Math.floor(Math.random() * responses.length)];

    // Show encouraging message with hint option
    const useHint = confirm(`${randomResponse}\n\nWould you like to use a hint? (This will deduct points)`);
    if (useHint) {
        showHintOptions(challengeId);
    }
}

function showHintOptions(challengeId) {
    const challenge = ctfChallenges[challengeId];
    let hintOptions = "Available hints:\n\n";

    challenge.hints.forEach((hint, index) => {
        const hintNum = index + 1;
        const alreadyUsed = usedHints[challengeId] && usedHints[challengeId].includes(hintNum);
        const status = alreadyUsed ? " (Already used)" : ` (-${hint.cost} points)`;
        hintOptions += `${hintNum}. ${hint.text}${status}\n\n`;
    });

    const hintChoice = prompt(hintOptions + "Enter hint number (1-3) or 0 to cancel:");
    if (hintChoice && hintChoice !== "0") {
        showHint(challengeId, parseInt(hintChoice));
    }
}

function addToRecentSubmissions(challengeTitle, points) {
    const submissionsContainer = document.getElementById('recent-submissions');
    const newSubmission = document.createElement('div');
    newSubmission.className = 'submission-item';
    newSubmission.style.background = 'rgba(16, 185, 129, 0.1)';
    newSubmission.style.borderColor = 'var(--success)';

    newSubmission.innerHTML = `
        <span class="submitter">🎉 You</span>
        <span class="challenge">${challengeTitle}</span>
        <span class="points">+${points} pts</span>
        <span class="time">Just now</span>
    `;

    submissionsContainer.insertBefore(newSubmission, submissionsContainer.firstChild);
}

function createCelebrationEffect() {
    // Create confetti effect
    for (let i = 0; i < 100; i++) {
        createConfetti();
    }
}

function createConfetti() {
    const confetti = document.createElement('div');
    confetti.style.position = 'fixed';
    confetti.style.left = Math.random() * window.innerWidth + 'px';
    confetti.style.top = '-10px';
    confetti.style.width = '10px';
    confetti.style.height = '10px';
    confetti.style.backgroundColor = ['#FFD700', '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'][Math.floor(Math.random() * 5)];
    confetti.style.borderRadius = '50%';
    confetti.style.pointerEvents = 'none';
    confetti.style.zIndex = '10000';
    confetti.style.animation = 'confetti-fall 3s linear infinite';

    document.body.appendChild(confetti);

    setTimeout(() => {
        confetti.remove();
    }, 3000);
}

function shareSuccess(challengeTitle, points) {
    const shareText = `🎉 I just solved "${challengeTitle}" and earned ${points} points in 2R-AT's Cybersecurity CTF Challenge! Think you can beat my score? 🔐 #CybersecurityCTF #2RAT #EthicalHacking`;

    if (navigator.share) {
        navigator.share({
            title: '2R-AT CTF Challenge Success!',
            text: shareText,
            url: window.location.href
        });
    } else {
        // Fallback to copying to clipboard
        navigator.clipboard.writeText(shareText).then(() => {
            alert('Achievement text copied to clipboard! Share it on your social media.');
        });
    }
}

function downloadCertificate(challengeTitle) {
    alert(`🏆 Your completion certificate for "${challengeTitle}" is being generated and will be emailed to you within 1 hour. This certificate is recognized by industry professionals and can be added to your LinkedIn profile!`);
}

function downloadReport(reportName) {
    console.log(`Download initiated for report: ${reportName}.pdf`);
    console.log(`User authenticated: ${auth.isAuthenticated()}`);
    showNotification(`Simulating download of: ${reportName}.pdf`, 'success');
}

function downloadEvidence(evidenceType) {
    const resources = {
        'laptop': 'laptop_forensic_image.dd - Full disk image of the suspect\'s work laptop (120GB). Use FTK Imager or Autopsy for analysis.',
        'mobile': 'mobile_extraction.tar - Complete mobile device extraction including apps, messages, call logs, and deleted data.'
    };

    alert(`📁 Downloading: ${resources[evidenceType]}\n\n⚠️ Note: This is a simulated download for demonstration purposes. In a real CTF, these would be actual forensic files for analysis.`);
}

// Enhanced Contact Form Handler
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
    if (auth.isAuthenticated()) {
        auth.updateUIForAuthenticatedUser();
    } else {
        auth.updateUIForUnauthenticatedUser();
    }

    // Add event listener for the quick scan button
    // const quickScanButtonOld = document.getElementById('quick-scan-button');
    // if (quickScanButtonOld) {
    //     quickScanButtonOld.addEventListener('click', handleQuickScan);
    // } else {
    //     console.error('Quick scan button not found on DOMContentLoaded');
    // }

    // Event listener for the Quick Scan button in the hero section
    const quickScanButtonHero = document.querySelector('.hero .btn-secondary[href="#quick-security-check"]');
    if (quickScanButtonHero) {
        quickScanButtonHero.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default anchor behavior
            // Smooth scroll to the Quick Security Check section
            const quickSecurityCheckSection = document.getElementById('quick-security-check');
            if (quickSecurityCheckSection) {
                quickSecurityCheckSection.scrollIntoView({ behavior: 'smooth' });
            }
        });
    }

    // Event listener for the Start Scan button in the Quick Security Check section
    const quickScanButton = document.getElementById('quick-scan-button');
    if (quickScanButton) {
        quickScanButton.addEventListener('click', function() {
            window.open('app.html', '_blank');
        });
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

    if (!userMenu.contains(event.target)) {
        dropdown.classList.remove('active');
    }
});

// Remove loader after page load
window.addEventListener('load', () => {
    setTimeout(() => {
        document.getElementById('loader').style.opacity = '0';
        setTimeout(() => {
            document.getElementById('loader').style.display = 'none';
        }, 500);
    }, 1000);
});

// Particle Effect
function createParticle() {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * window.innerWidth + 'px';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.opacity = Math.random() * 0.5 + 0.1;
    document.getElementById('particles').appendChild(particle);

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
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(5, 7, 20, 0.95)';
        navbar.style.boxShadow = '0 5px 20px rgba(0, 0, 0, 0.5)';
    } else {
        navbar.style.background = 'rgba(5, 7, 20, 0.9)';
        navbar.style.boxShadow = 'none';
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
        document.getElementById('user-dropdown').classList.remove('active');
    }
});

// Auto-save demo data periodically (simulated)
setInterval(() => {
    if (auth.isAuthenticated()) {
        // In a real app, this would sync with the server
        console.log('Auto-saving user data...');
    }
}, 30000); // Every 30 seconds

// Initial load setup
setTimeout(() => {
    if (!auth.isAuthenticated()) {
        auth.addProtectedOverlays();
    }
}, 1500);
