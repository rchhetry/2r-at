// Updated script.js for 2R-AT with app.html integration (Nessus components removed)

// Backend configuration
const BACKEND_URL = window.location.origin + '/api';

// Enhanced Success Stories Data with Comprehensive Content
const successStories = {
    banking: {
        title: "Global Financial Institution",
        icon: "🏦",
        subtitle: "Securing $50B+ in Assets Across 15 Countries",
        challenge: `When GlobalBank International approached 2R-AT Security in early 2024, they were facing a perfect storm of cybersecurity challenges. As one of the world's largest financial institutions with over $50 billion in managed assets across 50+ branches spanning 15 countries, they were experiencing an alarming 300% increase in sophisticated cyber attacks targeting their core banking infrastructure.

The institution was dealing with:
• Advanced Persistent Threats (APTs) specifically targeting SWIFT payment systems
• Insider threat incidents involving privileged access abuse
• Regulatory compliance gaps across multiple jurisdictions (SOX, PCI DSS, GDPR, Basel III)
• Legacy security systems creating visibility blind spots
• Inconsistent security policies across international branches
• Growing concern from board members about reputational and financial risk

The tipping point came when their existing security provider failed to detect a sophisticated social engineering attack that nearly resulted in a $2.3 million fraudulent wire transfer. The board mandated an immediate overhaul of their entire cybersecurity infrastructure with a requirement for zero tolerance on future breaches.`,

        solution: `2R-AT Security deployed our most comprehensive enterprise security transformation, implementing a cutting-edge zero-trust architecture designed specifically for global financial institutions:

**Phase 1: Rapid Assessment & Threat Containment (Weeks 1-4)**
• 24/7 Emergency Security Operations Center (SOC) deployment
• Comprehensive security audit across all 50+ locations
• Immediate implementation of advanced endpoint detection and response (EDR)
• Emergency incident response team stationed on-site at headquarters

**Phase 2: Zero-Trust Architecture Implementation (Months 2-6)**
• Complete network micro-segmentation isolating critical financial systems
• Implementation of our proprietary AI-powered threat detection engine
• Multi-factor authentication deployment for all 12,000+ employees and customers
• Advanced behavioral analytics for insider threat detection
• Secure remote access solutions for distributed workforce

**Phase 3: Advanced Security Controls & Compliance (Months 6-12)**
• Real-time transaction monitoring with ML-based fraud detection
• Automated compliance reporting for all regulatory requirements
• Advanced threat hunting services with dedicated security analysts
• Custom security awareness training for financial sector threats
• Integration with existing core banking systems without operational disruption

**Phase 4: Continuous Monitoring & Optimization (Ongoing)**
• 24/7/365 security monitoring with <50ms threat response time
• Quarterly penetration testing and security assessments
• Regular threat intelligence briefings for executive leadership
• Continuous security posture optimization based on emerging threats`,

        results: [
            "99.9% threat prevention rate across all global locations with zero successful breaches in 18 months",
            "50ms average response time for threat detection and automated containment",
            "Prevented $10.2M in attempted fraud and cybercrime across the network",
            "100% compliance achievement with all banking regulations (PCI DSS, SOX, Basel III) across 15 countries",
            "Zero successful data breaches or customer data compromises since implementation",
            "40% reduction in security false positives, dramatically improving SOC efficiency",
            "95% improvement in incident response time from hours to minutes",
            "Achieved cyber insurance premium reduction of 25% due to enhanced security posture",
            "$2.8M in operational cost savings through security automation and streamlined processes",
            "100% employee security awareness training completion with 90% improvement in phishing test results"
        ],

        metrics: {
            "Assets Protected": "$50B+",
            "Global Locations": "50+ branches",
            "Countries Secured": "15 nations",
            "Employees Protected": "12,000+",
            "Threat Response Time": "<50ms",
            "Compliance Rate": "100%",
            "ROI Achievement": "340%"
        },

        testimonial: "2R-AT Security's zero-trust implementation has fundamentally transformed our security posture. In 18 months, we've gone from being reactive to cyber threats to being proactively protected. Their team didn't just implement technology—they partnered with us to build a security culture that permeates every aspect of our operations. The peace of mind this gives our board, our customers, and our regulators is invaluable. We've seen a dramatic reduction in successful attacks while maintaining the performance our customers expect from a world-class financial institution.",
        author: "Maria Rodriguez, Chief Information Security Officer",
        company: "GlobalBank International",

        additionalDetails: {
            timeframe: "12-month implementation, ongoing partnership",
            teamSize: "15 dedicated 2R-AT security specialists",
            technologies: ["Zero Trust Network Access (ZTNA)", "Advanced EDR/XDR", "AI-Powered SIEM", "Behavioral Analytics", "Threat Intelligence Platform"],
            certifications: ["ISO 27001", "SOC 2 Type II", "PCI DSS Level 1", "NIST Cybersecurity Framework"]
        }
    },

    healthcare: {
        title: "Healthcare Network",
        icon: "🏥",
        subtitle: "Protecting 2M+ Patient Records Across Regional Medical Centers",
        challenge: `MedCare Regional Health System, encompassing 8 major hospitals and 25 outpatient clinics across the region, contacted 2R-AT Security after experiencing a series of cybersecurity incidents that threatened both patient care and regulatory compliance. Managing over 2 million patient records and processing thousands of daily medical transactions, they faced unprecedented challenges:

**Critical Security Gaps:**
• Outdated legacy medical systems with known vulnerabilities
• Inconsistent security policies across different facilities
• HIPAA compliance violations resulting in $1.2M in fines
• Ransomware attacks targeting medical imaging systems
• Insecure medical IoT devices creating network vulnerabilities
• Staff using personal devices without proper security controls

**Operational Challenges:**
• Medical staff frustrated by slow, cumbersome security procedures
• IT team overwhelmed managing security across multiple locations
• Board pressure to improve security without impacting patient care
• Regulatory scrutiny from HHS and state health departments
• Insurance companies threatening coverage reduction due to security gaps

The final straw came when a sophisticated ransomware attack encrypted critical patient imaging systems during a major cardiac surgery, forcing the hospital to operate without digital support. While patient care was not compromised, the incident highlighted the urgent need for comprehensive healthcare-specific cybersecurity measures.`,

        solution: `2R-AT Security implemented a comprehensive healthcare cybersecurity solution designed specifically for the unique requirements of medical environments:

**Phase 1: Emergency Response & Stabilization (Weeks 1-6)**
• Immediate deployment of healthcare-focused incident response team
• Complete security assessment of all medical devices and systems
• Emergency patching and hardening of critical patient care systems
• Implementation of network segmentation to isolate medical devices

**Phase 2: HIPAA-Compliant Security Architecture (Months 2-8)**
• Deployment of healthcare-specific SIEM with medical device monitoring
• Implementation of advanced data loss prevention (DLP) for protected health information (PHI)
• Secure mobile access solutions for medical staff with contextual authentication
• Advanced encryption for all patient data both at rest and in transit
• Real-time monitoring of all PHI access with automated audit trails

**Phase 3: Medical IoT & Device Security (Months 4-10)**
• Comprehensive medical device inventory and vulnerability assessment
• Network micro-segmentation for medical IoT devices (ventilators, monitors, infusion pumps)
• Implementation of medical device-specific threat detection
• Secure remote monitoring capabilities for telehealth services

**Phase 4: Staff Training & Compliance Automation (Months 6-12)**
• Comprehensive healthcare cybersecurity training for all 8,500 staff members
• Automated HIPAA compliance monitoring and reporting
• Regular phishing simulations with healthcare-specific scenarios
• Integration with existing electronic health record (EHR) systems

**Phase 5: Continuous Monitoring & Threat Intelligence (Ongoing)**
• 24/7 healthcare SOC with medical cybersecurity specialists
• Real-time threat intelligence focused on healthcare sector attacks
• Quarterly penetration testing of patient care systems
• Ongoing compliance monitoring and automated reporting`,

        results: [
            "100% HIPAA compliance maintained throughout implementation with zero violations in 24 months",
            "2M+ patient records secured with zero successful data breaches or PHI compromises",
            "30% improvement in secure data access speed for medical staff",
            "95% reduction in ransomware attempts with 100% prevention success rate",
            "24/7 monitoring of all PHI access with complete audit trail compliance",
            "99.8% staff cybersecurity training completion rate with 85% improvement in security awareness scores",
            "Zero patient care disruptions due to cybersecurity incidents since implementation",
            "Achieved cyber liability insurance premium reduction of 35%",
            "$3.2M in avoided regulatory fines through proactive compliance management",
            "98% medical staff satisfaction with new security procedures (up from 45%)"
        ],

        metrics: {
            "Patient Records Protected": "2M+",
            "Healthcare Facilities": "33 locations",
            "Medical Staff Secured": "8,500+",
            "Medical Devices Monitored": "15,000+",
            "HIPAA Compliance": "100%",
            "Uptime Achievement": "99.9%",
            "ROI": "285%"
        },

        testimonial: "Patient data security has always been our top priority, but we struggled to achieve both robust protection and operational efficiency. 2R-AT's healthcare-focused approach changed everything. They understood that in healthcare, security can't be an obstacle to patient care—it has to enable it. Their solution not only protected our patients' most sensitive information but actually improved our medical staff's ability to access critical data quickly and securely. The peace of mind knowing our patients' data is secure allows us to focus entirely on what we do best: providing exceptional healthcare.",
        author: "Dr. James Chen, Chief Medical Information Officer",
        company: "MedCare Regional Health System",

        additionalDetails: {
            timeframe: "12-month implementation across all facilities",
            teamSize: "12 healthcare cybersecurity specialists",
            technologies: ["Healthcare SIEM", "Medical Device Security", "PHI Encryption", "Secure Communication Platforms", "HIPAA Compliance Automation"],
            certifications: ["HIPAA Compliance", "HITECH Compliance", "SOC 2 Type II for Healthcare", "Healthcare Industry Cybersecurity Framework"]
        }
    },

    tech: {
        title: "Hypergrowth Tech Startup",
        icon: "🚀",
        subtitle: "Enabling 10x Growth While Maintaining Enterprise-Grade Security",
        challenge: `TechNova, a revolutionary AI-powered fintech startup, approached 2R-AT Security during a critical growth phase. Having recently secured $50M in Series B funding, they were experiencing explosive 10x growth while facing the challenge of building enterprise-grade security from the ground up. Their unique challenges included:

**Rapid Growth Challenges:**
• Scaling from 50 to 500+ employees in 12 months
• Expanding from 1 to 15 global offices across 3 continents
• Processing $100M+ in customer transactions monthly
• Managing explosive user growth from 10K to 1M+ active users
• Onboarding enterprise clients requiring SOC 2 compliance

**Security & Compliance Gaps:**
• Minimal security infrastructure due to rapid scaling priorities
• No formal incident response procedures or security policies
• Developer teams pushing code without security review processes
• Shadow IT proliferation with unmanaged cloud services
• Growing target for cybercriminals due to fintech sector and high profile

**Business Requirements:**
• Achieve SOC 2 Type II certification within 6 months for enterprise sales
• Maintain development velocity while implementing security controls
• Scale security infrastructure to support 10x user growth
• Build investor and customer confidence through demonstrable security posture
• Enable secure international expansion without security bottlenecks

The urgency escalated when a potential $10M enterprise client made SOC 2 compliance a hard requirement for their contract, with a 6-month deadline that seemed impossible to meet given their current security maturity.`,

        solution: `2R-AT Security implemented an innovative "secure-by-design" approach that enabled rapid scaling while building enterprise-grade security:

**Phase 1: Rapid Security Foundation (Months 1-2)**
• Emergency security assessment and risk prioritization
• Implementation of cloud-native security architecture on AWS and Azure
• Deployment of zero-trust network access for remote workforce
• Basic security policies and incident response procedures
• Immediate DevSecOps integration into existing CI/CD pipelines

**Phase 2: DevSecOps & Development Security (Months 2-4)**
• Security-first development practices training for all engineering teams
• Automated security testing integration into development workflows
• Implementation of secrets management and secure code repositories
• Container security and Kubernetes hardening for microservices architecture
• Real-time vulnerability scanning and automated remediation

**Phase 3: Compliance & Governance (Months 3-6)**
• SOC 2 Type II readiness assessment and gap remediation
• Implementation of comprehensive audit logging and monitoring
• Data classification and protection policies for customer financial data
• Third-party risk management program for vendor relationships
• Automated compliance monitoring and evidence collection

**Phase 4: Advanced Security Operations (Months 4-8)**
• 24/7 security operations center (SOC) deployment
• Advanced threat detection with AI-powered behavioral analytics
• Customer data protection with field-level encryption
• Identity and access management (IAM) for all systems and applications
• Advanced threat intelligence integration for fintech-specific threats

**Phase 5: Global Scaling & Optimization (Months 6-12)**
• Multi-region security architecture for international expansion
• Localized compliance support for international data protection laws
• Advanced fraud detection and prevention for customer transactions
• Continuous security posture optimization based on growth metrics
• Executive security governance and board-level reporting`,

        results: [
            "Successfully supported 10x business growth from 50 to 500+ employees without security incidents",
            "Zero security incidents during rapid scaling period with 1M+ user growth",
            "100% automated security testing integration in development pipelines",
            "SOC 2 Type II certification achieved in 5.5 months (ahead of 6-month deadline)",
            "50% faster secure product deployment through DevSecOps automation",
            "Enterprise customer trust enabling $50M+ in new contract wins",
            "99.9% system uptime maintained during explosive growth phase",
            "Achieved Series C funding of $120M with security posture as competitive advantage",
            "$8M in enterprise deals closed directly attributed to security compliance",
            "Developer productivity increased 25% through security automation and streamlined processes"
        ],

        metrics: {
            "Growth Supported": "10x (50 to 500+ employees)",
            "User Growth": "100x (10K to 1M+ users)",
            "Transaction Volume": "$100M+ monthly",
            "Global Offices": "15 locations",
            "Deployment Speed": "50% faster",
            "Compliance Time": "5.5 months to SOC 2",
            "ROI": "450%"
        },

        testimonial: "2R-AT Security didn't just implement security for us—they enabled our growth. In the startup world, security is often seen as a brake on innovation and speed. 2R-AT flipped that paradigm entirely. Their secure-by-design approach meant we could scale rapidly while actually strengthening our security posture. When enterprise clients asked about our security capabilities, we went from having to make excuses to being able to showcase our robust, compliant infrastructure as a competitive advantage. They understood that for a hypergrowth startup, security needs to be an accelerator, not an obstacle.",
        author: "Sarah Kim, Co-founder & CTO",
        company: "TechNova AI",

        additionalDetails: {
            timeframe: "12-month security transformation during hypergrowth",
            teamSize: "8 dedicated startup security specialists",
            technologies: ["Cloud-Native Security", "DevSecOps Pipeline", "Zero Trust Architecture", "AI-Powered Threat Detection", "Automated Compliance"],
            certifications: ["SOC 2 Type II", "ISO 27001", "Cloud Security Alliance", "DevSecOps Maturity Model"]
        }
    }
};

// Enhanced function to show success story details with rich content
function showSuccessStory(storyId) {
    const story = successStories[storyId];
    if (!story) {
        console.error('Story not found:', storyId);
        return;
    }

    const detailSection = document.getElementById('success-story-detail');
    const contentDiv = document.getElementById('story-detail-content');

    if (!detailSection || !contentDiv) {
        console.error('Required DOM elements not found');
        return;
    }

    // Create the comprehensive detailed content
    const content = `
        <div class="story-detail-header" style="text-align: center; margin-bottom: 4rem;">
            <div class="story-detail-icon" style="font-size: 5rem; margin-bottom: 1rem;">${story.icon}</div>
            <h1 class="section-title">${story.title}</h1>
            <p style="font-size: 1.3rem; color: var(--primary); margin-bottom: 2rem;">${story.subtitle}</p>
            <div style="text-align: center; margin: 2rem 0;">
                <a href="#success-stories" class="btn btn-secondary" onclick="hideSuccessStory()">← Back to Success Stories</a>
            </div>
        </div>

        <div class="story-detail-body" style="max-width: 1000px; margin: 0 auto;">
            <!-- Key Metrics Section -->
            <div class="story-section" style="margin-bottom: 3rem; background: linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(255, 0, 110, 0.1));">
                <h3 style="color: var(--primary); margin-bottom: 2rem; text-align: center;">📊 Key Results Overview</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem;">
                    ${Object.entries(story.metrics).map(([key, value]) => `
                        <div style="background: rgba(0, 0, 0, 0.3); padding: 1.5rem; border-radius: 10px; text-align: center; border: 1px solid rgba(0, 212, 255, 0.2);">
                            <div style="font-size: 1.8rem; font-weight: bold; color: var(--primary); margin-bottom: 0.5rem;">${value}</div>
                            <div style="color: var(--gray); font-size: 0.9rem;">${key}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Challenge Section -->
            <div class="story-section" style="margin-bottom: 3rem;">
                <h3 style="color: var(--danger); margin-bottom: 1.5rem;">🎯 The Challenge</h3>
                <div style="color: var(--gray); line-height: 1.7; font-size: 1.1rem; white-space: pre-line;">${story.challenge}</div>
            </div>

            <!-- Solution Section -->
            <div class="story-section" style="margin-bottom: 3rem;">
                <h3 style="color: var(--primary); margin-bottom: 1.5rem;">🛡️ Our Comprehensive Solution</h3>
                <div style="color: var(--gray); line-height: 1.7; font-size: 1.1rem; white-space: pre-line;">${story.solution}</div>
            </div>

            <!-- Results Section -->
            <div class="story-section" style="margin-bottom: 3rem;">
                <h3 style="color: var(--success); margin-bottom: 1.5rem;">📈 Measurable Results Achieved</h3>
                <div style="display: grid; gap: 1rem;">
                    ${story.results.map(result => `
                        <div style="display: flex; align-items: flex-start; padding: 1rem; background: rgba(16, 185, 129, 0.1); border-radius: 8px; border-left: 4px solid var(--success);">
                            <span style="color: var(--success); font-size: 1.2rem; margin-right: 1rem; margin-top: 0.2rem;">✓</span>
                            <span style="color: var(--light); line-height: 1.6;">${result}</span>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Implementation Details -->
            <div class="story-section" style="margin-bottom: 3rem;">
                <h3 style="color: var(--warning); margin-bottom: 1.5rem;">⚙️ Implementation Details</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem;">
                    <div style="background: rgba(0, 0, 0, 0.2); padding: 1.5rem; border-radius: 10px;">
                        <h4 style="color: var(--primary); margin-bottom: 1rem;">⏱️ Project Timeline</h4>
                        <p style="color: var(--light);">${story.additionalDetails.timeframe}</p>
                    </div>
                    <div style="background: rgba(0, 0, 0, 0.2); padding: 1.5rem; border-radius: 10px;">
                        <h4 style="color: var(--primary); margin-bottom: 1rem;">👥 Team Size</h4>
                        <p style="color: var(--light);">${story.additionalDetails.teamSize}</p>
                    </div>
                    <div style="background: rgba(0, 0, 0, 0.2); padding: 1.5rem; border-radius: 10px;">
                        <h4 style="color: var(--primary); margin-bottom: 1rem;">🔧 Technologies Used</h4>
                        <ul style="list-style: none; padding: 0; color: var(--light);">
                            ${story.additionalDetails.technologies.map(tech => `<li style="margin-bottom: 0.5rem;">• ${tech}</li>`).join('')}
                        </ul>
                    </div>
                    <div style="background: rgba(0, 0, 0, 0.2); padding: 1.5rem; border-radius: 10px;">
                        <h4 style="color: var(--primary); margin-bottom: 1rem;">🏆 Certifications</h4>
                        <ul style="list-style: none; padding: 0; color: var(--light);">
                            ${story.additionalDetails.certifications.map(cert => `<li style="margin-bottom: 0.5rem;">• ${cert}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Testimonial Section -->
            <div class="story-section" style="margin-bottom: 3rem;">
                <h3 style="color: var(--secondary); margin-bottom: 1.5rem;">💬 Client Testimonial</h3>
                <blockquote style="
                    background: linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(255, 0, 110, 0.1));
                    border-left: 4px solid var(--primary);
                    padding: 2.5rem;
                    border-radius: 15px;
                    font-style: italic;
                    color: var(--light);
                    margin: 0;
                    position: relative;
                    font-size: 1.1rem;
                    line-height: 1.8;
                ">
                    <span style="font-size: 4rem; color: var(--primary); position: absolute; top: 1rem; left: 1.5rem; line-height: 1; opacity: 0.7;">"</span>
                    <div style="margin-left: 3rem;">${story.testimonial}</div>
                    <footer style="margin-top: 2rem; font-style: normal; color: var(--primary); font-weight: bold; text-align: right; margin-left: 3rem;">
                        — ${story.author}<br>
                        <span style="color: var(--gray); font-weight: normal; font-size: 0.9rem;">${story.company}</span>
                    </footer>
                </blockquote>
            </div>

            <!-- Call to Action Section -->
            <div style="text-align: center; margin-top: 4rem; padding: 3rem; background: linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(255, 0, 110, 0.1)); border-radius: 20px;">
                <h3 style="color: var(--primary); margin-bottom: 2rem; font-size: 2rem;">Ready to Transform Your Security Like ${story.title.split(' ')[0]}?</h3>
                <p style="color: var(--gray); margin-bottom: 2rem; font-size: 1.1rem; max-width: 600px; margin-left: auto; margin-right: auto;">Join hundreds of organizations that have transformed their security posture with 2R-AT's enterprise-grade cybersecurity solutions.</p>
                <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                    <a href="#contact" class="btn btn-primary" style="margin: 0.5rem;">Get Your Security Assessment</a>
                    <a href="#plans" class="btn btn-secondary" style="margin: 0.5rem;">View Our Plans</a>
                    <a href="#managed-security-services" class="btn btn-secondary" style="margin: 0.5rem;">Explore Services</a>
                </div>
            </div>
        </div>
    `;

    contentDiv.innerHTML = content;
    detailSection.style.display = 'block';
    detailSection.scrollIntoView({ behavior: 'smooth' });
}

// Function to hide success story details
function hideSuccessStory() {
    const detailSection = document.getElementById('success-story-detail');
    if (detailSection) {
        detailSection.style.display = 'none';
        document.getElementById('success-stories').scrollIntoView({ behavior: 'smooth' });
    }
}

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

// Initialize systems
const auth = new AuthSystem();

// NEW: Direct Security Scan Launch Function
function launchSecurityScan() {
    // Open the security scanning platform directly
    window.open('/app.html', '_blank');
    
    // Show notification to user
    showNotification('Security scanning platform launched in new window', 'success');
}

// CTF Challenges and other existing functions...
const ctfFlags = {
    'web-app': '2R-AT{sql_inj3ct1on_4ttack_succ3ss}',
    'web-login-bypass': '2R-AT{admin_bypass_weak_auth}',
    'crypto-ancient-cipher': '2R-AT{crypt0_c43s4r_sh1ft_k3y15}'
};

const ctfHints = {
    'web-app': [
        "Look for input fields that might not be properly sanitized",
        "Try using SQL injection techniques on the login form",
        "The vulnerability is in the username field - try: admin' OR '1'='1"
    ],
    'web-login-bypass': [
        "Try common default credentials first",
        "Check the browser's developer tools for client-side authentication",
        "Look for JavaScript that validates credentials locally"
    ],
    'crypto-ancient-cipher': [
        "This is a classic substitution cipher from ancient Rome",
        "Each letter is shifted by a fixed number of positions in the alphabet",
        "Try Caesar cipher with a shift of 15 positions backward"
    ]
};

function showHint(challengeId, hintNumber) {
    if (!auth.isAuthenticated()) {
        showAuthModal('login');
        return;
    }

    const hint = ctfHints[challengeId]?.[hintNumber - 1];
    if (hint) {
        alert(`Hint ${hintNumber}: ${hint}`);
    } else {
        alert('No more hints available for this challenge.');
    }
}

function submitFlag(challengeId) {
    if (!auth.isAuthenticated()) {
        showAuthModal('login');
        return;
    }

    const input = document.getElementById(`flag-${challengeId}`);
    const userFlag = input.value.trim();
    const correctFlag = ctfFlags[challengeId];

    if (userFlag === correctFlag) {
        // Success!
        const resultSection = document.getElementById('your-results');
        const resultContent = document.getElementById('result-content');
        
        resultContent.innerHTML = `
            <h4>🎊 Challenge Completed Successfully!</h4>
            <div class="result-details">
                <div class="result-detail">
                    <div class="label">Challenge</div>
                    <div class="value">${challengeId}</div>
                </div>
                <div class="result-detail">
                    <div class="label">Points Earned</div>
                    <div class="value">+${getPointsForChallenge(challengeId)}</div>
                </div>
                <div class="result-detail">
                    <div class="label">Rank Progress</div>
                    <div class="value">Advanced</div>
                </div>
            </div>
            <p style="color: var(--gray); margin-top: 2rem;">Great work! You've successfully solved this security challenge. Keep exploring our other challenges to improve your skills.</p>
        `;
        
        resultSection.style.display = 'block';
        resultSection.scrollIntoView({ behavior: 'smooth' });
        
        // Clear the input
        input.value = '';
        
        showNotification('Congratulations! Challenge solved successfully!', 'success');
    } else {
        showNotification('Incorrect flag. Try again!', 'error');
    }
}

function getPointsForChallenge(challengeId) {
    const points = {
        'web-app': 1000,
        'web-login-bypass': 750,
        'crypto-ancient-cipher': 550
    };
    return points[challengeId] || 0;
}

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

// Contact Form Handler
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

// Report Download Functions
function downloadReport(reportId) {
    const reports = {
        'threat-landscape-2025': {
            title: '2025 Cyber Threat Landscape Report',
            content: 'This comprehensive report analyzes emerging threats in 2025...'
        },
        'apt-analysis-q4': {
            title: 'APT Groups Activity Analysis Q4 2024',
            content: 'Deep dive into nation-state threat actor activities...'
        },
        'cloud-benchmark-2025': {
            title: 'Cloud Security Benchmark 2025',
            content: 'Industry benchmarks for cloud security posture...'
        }
    };

    const report = reports[reportId];
    if (report) {
        // Create a simple text file download
        const blob = new Blob([`${report.title}\n\n${report.content}`], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${reportId}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('Report downloaded successfully!', 'success');
    } else {
        showNotification('Report not found', 'error');
    }
}

// Initialize UI based on authentication status
document.addEventListener('DOMContentLoaded', () => {
    // Initialize success stories functionality
    console.log('Enhanced success stories functionality loaded');
});

// Handle back button clicks in success story details
document.addEventListener('click', function(e) {
    if (e.target.textContent.includes('← Back to Success Stories')) {
        e.preventDefault();
        hideSuccessStory();
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
