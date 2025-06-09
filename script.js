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
            'web-login-bypass': {
                title: 'Admin Portal Bypass',
                correctFlag: '2R-AT{w3b_byp4ss_fl4g_h3r3}',
                points: 750,
                hints: [
                    { text: "Check for weak credentials or default passwords.", cost: 30 },
                    { text: "Inspect client-side JavaScript for any authentication logic that can be manipulated.", cost: 70 },
                    { text: "Try common SQL injection payloads in the username and password fields.", cost: 100 }
                ]
            },
            'crypto-ancient-cipher': {
                title: 'Ancient Message Decryption',
                correctFlag: '2R-AT{crypt0_c43s4r_sh1ft_k3y15}',
                points: 550,
                hints: [
                    { text: "The ciphertext seems to be a simple substitution cipher. Maybe Caesar?", cost: 20 },
                    { text: "Frequency analysis might reveal common letters.", cost: 50 },
                    { text: "The key is a single digit number representing the shift.", cost: 80 }
                ]
            }
        };

        const ctfPrizes = {
            1000: { rank: "🏆 EXPERT LEVEL", bonus: "You've earned an Internship Opportunity at 2R-AT + a $200 Gift Voucher + Movie Tickets for two!", bg: "linear-gradient(135deg, #FFD700, #FFA500)" },
            800: { rank: "🥈 ADVANCED LEVEL", bonus: "You've earned a $150 Gift Voucher + a 1-Year Pre-paid Mobile Topoff + access to our advanced training!", bg: "linear-gradient(135deg, #C0C0C0, #A0A0A0)" },
            600: { rank: "🥉 INTERMEDIATE LEVEL", bonus: "You've earned a $100 Gift Voucher + Movie Tickets for one + free certification voucher!", bg: "linear-gradient(135deg, #CD7F32, #B8860B)" },
            400: { rank: "🎯 BEGINNER LEVEL", bonus: "You've earned a $50 Pre-paid Mobile Topoff + training course access!", bg: "linear-gradient(135deg, #32CD32, #228B22)" }
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
            // Actual download logic would go here in a real application
            // For example, creating an anchor element and triggering a click:
            // const link = document.createElement('a');
            // link.href = `/reports/${reportName}.pdf`; // Path to the report
            // link.download = `${reportName}.pdf`;
            // document.body.appendChild(link);
            // link.click();
            // document.body.removeChild(link);
        }

        function downloadEvidence(evidenceType) {
            const resources = {
                'laptop': 'laptop_forensic_image.dd - Full disk image of the suspect\'s work laptop (120GB). Use FTK Imager or Autopsy for analysis.',
                'mobile': 'mobile_extraction.tar - Complete mobile device extraction including apps, messages, call logs, and deleted data.'
            };

            alert(`📁 Downloading: ${resources[evidenceType]}\n\n⚠️ Note: This is a simulated download for demonstration purposes. In a real CTF, these would be actual forensic files for analysis.`);
        }

// Dynamic Quick Scan Functionality
function handleQuickScan() {
    const targetInput = document.getElementById('quick-scan-target');
    const scanButton = document.getElementById('quick-scan-button');
    const outputElement = document.getElementById('quick-scan-output');
    const resultsElement = document.getElementById('quick-scan-results');

    if (!targetInput || !scanButton || !outputElement || !resultsElement) {
        console.error('Quick scan elements not found!');
        return;
    }

    const targetValue = targetInput.value.trim();
    if (!targetValue) {
        outputElement.innerHTML = 'Please enter a target (e.g., your-website.com) to scan.';
        resultsElement.innerHTML = ''; // Clear previous results
        return;
    }

    scanButton.disabled = true;
    targetInput.disabled = true;
    outputElement.innerHTML = ''; // Clear previous output
    resultsElement.innerHTML = ''; // Clear previous results

    const steps = [
        `$ 2R-AT --scan --target ${targetValue}`,
        "[+] Initializing security scan...",
        "[+] Checking DNS records and open ports...",
        "[+] Analyzing web application firewalls...",
        `[+] Scanning ${Math.floor(Math.random() * 500) + 50} common vulnerabilities...`,
        "[+] Cross-referencing with threat intelligence feeds..."
    ];

    let currentStep = 0;
    function displayNextStep() {
        if (currentStep < steps.length) {
            outputElement.innerHTML += (currentStep > 0 ? '<br>' : '') + steps[currentStep];
            currentStep++;
            setTimeout(displayNextStep, Math.random() * 500 + 200); // Shorter delay for steps
        } else {
            // Simulate scan completion
            const vulnerabilitiesFound = Math.random() < 0.4 ? Math.floor(Math.random() * 5) + 1 : 0; // 40% chance of finding vulnerabilities

            outputElement.innerHTML += `<br>[+] Analysis complete. Vulnerabilities detected: ${vulnerabilitiesFound}`;
            outputElement.innerHTML += `<br>[+] Security status: ${vulnerabilitiesFound > 0 ? '<span style="color:var(--warning);">ACTION REQUIRED</span>' : '<span style="color:var(--success);">PROTECTED ✓</span>'}`;

            if (vulnerabilitiesFound > 0) {
                resultsElement.innerHTML = `
                    <p style="color:var(--warning); font-weight:bold;">${vulnerabilitiesFound} potential issue(s) found during this quick scan.</p>
                    <p>This initial scan provides a high-level overview. For a detailed report, comprehensive analysis, and mitigation strategies, please get in touch with our experts.</p>
                    <a href="#contact" class="btn btn-primary" style="margin-top:1rem;">Contact Security Experts</a>
                `;
            } else {
                resultsElement.innerHTML = `
                    <p style="color:var(--success); font-weight:bold;">No critical vulnerabilities detected in this quick scan.</p>
                    <p>While this scan didn't find immediate critical issues, a comprehensive security assessment is recommended for thorough protection. Explore our services or contact us for more details.</p>
                    <a href="#security-assessment" class="btn btn-secondary" style="margin-top:0.5rem; margin-right:0.5rem;">Explore Assessments</a>
                    <a href="#contact" class="btn btn-primary" style="margin-top:0.5rem;">Contact Us</a>
                `;
            }

            scanButton.disabled = false;
            targetInput.disabled = false;
        }
    }
    displayNextStep(); // Start displaying steps
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

        // Add event listener after DOM is loaded
        document.addEventListener('DOMContentLoaded', () => {
            const scanButton = document.getElementById('quick-scan-button');
            if (scanButton) {
                scanButton.addEventListener('click', handleQuickScan);
            }

            // Initialize UI based on authentication status
            if (auth.isAuthenticated()) {
                auth.updateUIForAuthenticatedUser();
            } else {
                auth.updateUIForUnauthenticatedUser();
            }

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

                if (userMenu && !userMenu.contains(event.target)) { // Ensure userMenu exists
                    dropdown.classList.remove('active');
                }
            });

            // Remove loader after page load (consolidated from window.onload)
            const loader = document.getElementById('loader');
            if (loader) {
                 // Using 'load' event on window inside DOMContentLoaded might be tricky.
                 // It's generally better to trigger loader removal after initial setup.
                 // For simplicity here, we'll assume direct execution or a more robust page load check.
                setTimeout(() => {
                    loader.style.opacity = '0';
                    setTimeout(() => {
                        loader.style.display = 'none';
                    }, 500);
                }, 1000);
            }
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
