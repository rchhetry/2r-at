// --- Start of Merged JavaScript ---

// Data objects from comprehensive_js_content
const trainingDetails = {
    'security-awareness': {
        icon: '🧠',
        title: 'Security Awareness Training',
        subtitle: 'Transform your employees into human firewalls',
        description: 'Our comprehensive security awareness program is designed to educate and empower your workforce to recognize, avoid, and report cyber threats. Through interactive learning modules, real-world simulations, and continuous reinforcement, we create a culture of security within your organization.',
        duration: '4-8 weeks',
        level: 'All Levels',
        format: 'Hybrid (Online + In-Person)',
        certificationOffered: 'Security Awareness Certificate',
        features: [
            'Interactive phishing simulation campaigns',
            'Role-based security training modules',
            'Real-world social engineering scenarios',
            'Mobile security best practices',
            'Password security and MFA training',
            'Data protection and privacy awareness',
            'Incident reporting procedures',
            'Quarterly security updates and refreshers'
        ],
        curriculum: [
            { module: 'Introduction to Cybersecurity', duration: '2 hours', desc: 'Understanding the threat landscape and basic security principles' },
            { module: 'Email Security & Phishing', duration: '3 hours', desc: 'Identifying and avoiding phishing attacks and malicious emails' },
            { module: 'Password Security & Authentication', duration: '2 hours', desc: 'Creating strong passwords and using multi-factor authentication' },
            { module: 'Social Engineering Awareness', duration: '2 hours', desc: 'Recognizing and defending against social engineering tactics' },
            { module: 'Data Protection & Privacy', duration: '2 hours', desc: 'Handling sensitive data and understanding privacy regulations' },
            { module: 'Mobile & Remote Work Security', duration: '2 hours', desc: 'Securing mobile devices and working safely from home' },
            { module: 'Incident Response & Reporting', duration: '1 hour', desc: 'What to do when a security incident occurs' }
        ],
        pricing: 'Starting at $99 per employee',
        benefits: [
            { title: 'Reduce Human Error', desc: 'Decrease security incidents caused by employee mistakes by up to 85%' },
            { title: 'Compliance Ready', desc: 'Meet regulatory training requirements for GDPR, HIPAA, and other frameworks' },
            { title: 'Measurable Results', desc: 'Track progress with detailed analytics and reporting dashboards' },
            { title: 'Continuous Learning', desc: 'Keep your team updated with the latest threats and best practices' }
        ]
    },
    'risk-management': {
        icon: '⚖️',
        title: 'Risk Management Certification',
        subtitle: 'Master enterprise risk assessment and mitigation',
        description: 'Develop expertise in identifying, assessing, and mitigating cybersecurity risks using industry-leading frameworks. This comprehensive program prepares professionals to build robust risk management programs that align with business objectives.',
        duration: '12 weeks',
        level: 'Intermediate to Advanced',
        format: 'Live Virtual + Self-Paced',
        certificationOffered: 'Certified Risk Management Professional (CRMP)',
        features: [
            'NIST Risk Management Framework (RMF)',
            'ISO 27001/27005 risk assessment methodologies',
            'Business impact analysis and continuity planning',
            'Quantitative and qualitative risk analysis',
            'Risk treatment and mitigation strategies',
            'Regulatory compliance frameworks',
            'Risk communication and reporting',
            'Continuous monitoring and assessment'
        ],
        curriculum: [
            { module: 'Risk Management Fundamentals', duration: '8 hours', desc: 'Core concepts, terminology, and risk management lifecycle' },
            { module: 'Risk Assessment Methodologies', duration: '12 hours', desc: 'NIST, ISO 27005, FAIR, and other leading frameworks' },
            { module: 'Asset Identification & Valuation', duration: '6 hours', desc: 'Cataloging and valuing organizational assets' },
            { module: 'Threat & Vulnerability Analysis', duration: '10 hours', desc: 'Identifying and analyzing potential threats and vulnerabilities' },
            { module: 'Risk Analysis & Calculation', duration: '8 hours', desc: 'Quantitative and qualitative risk analysis techniques' },
            { module: 'Risk Treatment & Controls', duration: '10 hours', desc: 'Selecting and implementing appropriate risk treatments' },
            { module: 'Business Continuity & Disaster Recovery', duration: '8 hours', desc: 'Ensuring business resilience through proper planning' },
            { module: 'Compliance & Regulatory Requirements', duration: '6 hours', desc: 'Meeting industry-specific compliance obligations' },
            { module: 'Risk Monitoring & Review', duration: '4 hours', desc: 'Continuous monitoring and improvement processes' },
            { module: 'Capstone Project', duration: '16 hours', desc: 'Real-world risk assessment project' }
        ],
        pricing: 'Starting at $2,999 per participant',
        benefits: [
            { title: 'Industry Recognition', desc: 'Earn credentials recognized by leading organizations worldwide' },
            { title: 'Career Advancement', desc: 'Qualify for senior risk management and CISO positions' },
            { title: 'Practical Skills', desc: 'Apply learning immediately with hands-on projects and case studies' },
            { title: 'Expert Network', desc: 'Join our exclusive community of certified risk professionals' }
        ]
    },
    'ethical-hacking': {
        icon: '🎭',
        title: 'Ethical Hacking Bootcamp',
        subtitle: 'Master the art of penetration testing',
        description: 'Intensive hands-on training in ethical hacking and penetration testing. Learn to think like an attacker to better defend your organization. This immersive program covers the latest tools, techniques, and methodologies used by security professionals worldwide.',
        duration: '16 weeks',
        level: 'Advanced',
        format: 'Immersive Lab Environment',
        certificationOffered: 'Certified Ethical Hacker Professional (CEHP)',
        features: [
            'Comprehensive network penetration testing',
            'Advanced web application security testing',
            'Mobile application penetration testing',
            'Wireless network security assessment',
            'Social engineering and physical security',
            'Cloud infrastructure penetration testing',
            'Active Directory and domain attacks',
            'Real-world capture-the-flag challenges'
        ],
        curriculum: [
            { module: 'Introduction to Ethical Hacking', duration: '8 hours', desc: 'Legal and ethical considerations, methodology overview' },
            { module: 'Reconnaissance & Information Gathering', duration: '12 hours', desc: 'OSINT, footprinting, and target reconnaissance' },
            { module: 'Scanning & Enumeration', duration: '16 hours', desc: 'Network discovery, port scanning, and service enumeration' },
            { module: 'System Hacking & Exploitation', duration: '20 hours', desc: 'Vulnerability exploitation and system compromise' },
            { module: 'Malware & Trojans', duration: '8 hours', desc: 'Understanding and detecting malicious software' },
            { module: 'Sniffing & Session Hijacking', duration: '12 hours', desc: 'Network traffic analysis and session attacks' },
            { module: 'Social Engineering', duration: '8 hours', desc: 'Human-based attack vectors and defenses' },
            { module: 'Denial of Service Attacks', duration: '8 hours', desc: 'DoS/DDoS attack methods and mitigation' },
            { module: 'Web Application Hacking', duration: '24 hours', desc: 'OWASP Top 10 and advanced web security testing' },
            { module: 'Wireless Network Hacking', duration: '12 hours', desc: 'WiFi security assessment and attacks' },
            { module: 'Mobile Platform Attacks', duration: '16 hours', desc: 'iOS and Android security testing' },
            { module: 'IoT & Cloud Security', duration: '12 hours', desc: 'Emerging platform security assessment' },
            { module: 'Cryptography & PKI', duration: '8 hours', desc: 'Cryptographic attacks and implementations' },
            { module: 'Final Capstone Project', duration: '32 hours', desc: 'Comprehensive penetration test of simulated environment' }
        ],
        pricing: 'Starting at $8,999 per participant',
        benefits: [
            { title: 'Hands-On Experience', desc: 'Real-world lab environments with vulnerable systems and applications' },
            { title: 'Industry Tools', desc: 'Training on professional-grade penetration testing tools and frameworks' },
            { title: 'Expert Instruction', desc: 'Learn from active penetration testers and security researchers' },
            { title: 'Career Placement', desc: 'Job placement assistance and direct connections to hiring partners' }
        ]
    },
    'digital-forensics': {
        icon: '🔬',
        title: 'Digital Forensics Bootcamp',
        subtitle: 'Investigate cyber crimes and security incidents',
        description: 'Comprehensive training in digital forensics and incident response. Learn to collect, analyze, and present digital evidence in legal proceedings. This program combines technical skills with legal knowledge to prepare forensic investigators for real-world challenges.',
        duration: '20 weeks',
        level: 'Advanced',
        format: 'Lab-Intensive + Legal Training',
        certificationOffered: 'Certified Digital Forensics Examiner (CDFE)',
        features: [
            'Digital evidence acquisition and preservation',
            'File system and memory analysis',
            'Network forensics and packet analysis',
            'Mobile device forensics (iOS/Android)',
            'Cloud forensics and investigations',
            'Malware analysis and reverse engineering',
            'Legal procedures and court testimony',
            'Incident response and threat hunting'
        ],
        curriculum: [
            { module: 'Introduction to Digital Forensics', duration: '8 hours', desc: 'Fundamentals, legal framework, and best practices' },
            { module: 'Digital Evidence Handling', duration: '12 hours', desc: 'Chain of custody, acquisition, and preservation' },
            { module: 'File System Forensics', duration: '16 hours', desc: 'NTFS, FAT, ext4, and other file system analysis' },
            { module: 'Windows Forensics', duration: '20 hours', desc: 'Registry analysis, artifacts, and timeline reconstruction' },
            { module: 'Linux/Unix Forensics', duration: '16 hours', desc: 'Log analysis, shell artifacts, and system examination' },
            { module: 'Memory Forensics', duration: '16 hours', desc: 'RAM analysis, process investigation, and malware detection' },
            { module: 'Network Forensics', duration: '16 hours', desc: 'Packet analysis, protocol investigation, and traffic reconstruction' },
            { module: 'Mobile Device Forensics', duration: '20 hours', desc: 'iOS and Android acquisition and analysis' },
            { module: 'Cloud Forensics', duration: '12 hours', desc: 'Cloud service provider investigations and challenges' },
            { module: 'Malware Analysis', duration: '16 hours', desc: 'Static and dynamic malware analysis techniques' },
            { module: 'Database Forensics', duration: '8 hours', desc: 'Database investigation and recovery techniques' },
            { module: 'Email Forensics', duration: '8 hours', desc: 'Email header analysis and message recovery' },
            { module: 'Legal Aspects & Testimony', duration: '12 hours', desc: 'Legal procedures, report writing, and expert testimony' },
            { module: 'Incident Response Integration', duration: '8 hours', desc: 'Coordinating forensics with incident response' },
            { module: 'Final Capstone Investigation', duration: '40 hours', desc: 'Complete forensic investigation with legal documentation' }
        ],
        pricing: 'Starting at $12,999 per participant',
        benefits: [
            { title: 'Legal Training', desc: 'Understand legal requirements and court procedures for digital evidence' },
            { title: 'Real Cases', desc: 'Work on sanitized real-world cases and scenarios' },
            { title: 'Tool Mastery', desc: 'Hands-on experience with industry-standard forensic tools' },
            { title: 'Expert Network', desc: 'Access to practicing forensic examiners and legal professionals' }
        ]
    }
};
const caseStudyDetails = {
    'financial-institution': { title: "Global Financial Institution", icon: "🏦", problem: "Needed to secure a sprawling network of branches and digital services against sophisticated fraud attempts and ensure compliance with international financial regulations.", solution: "Implemented a Zero Trust architecture across all 50+ branches and online platforms. Deployed AI-driven threat detection and automated response systems. Conducted continuous penetration testing and vulnerability assessments.", results: [{value:"$10M+", label:"Potential Fraud Prevented Annually"}, {value:"99.99%", label:"Uptime of Critical Systems"}, {value:"<50ms", label:"Average Threat Response Time"}, {value:"100%", label:"Compliance with PCI-DSS & Swift CSP"}], testimonial: "2R-AT's expertise transformed our security posture, allowing us to innovate confidently while protecting our customers' assets.", image: "img/case-study-finance.jpg" },
    'healthcare-network': { title: "Major Healthcare Network", icon: "🏥", problem: "Faced challenges in securing over 2 million patient records (EHR) while maintaining HIPAA compliance and enabling seamless data access for authorized medical personnel.", solution: "Developed a multi-layered security strategy including endpoint detection and response (EDR), network segmentation, and advanced encryption for data at rest and in transit. Provided comprehensive HIPAA compliance training for all staff.", results: [{value:"2M+", label:"Patient Records Secured"}, {value:"100%", label:"HIPAA & HITECH Compliance"}, {value:"0", label:"Data Breaches Since Implementation"}, {value:"70%", label:"Reduction in Phishing Incidents"}], testimonial: "The 2R-AT team provided an exceptional solution that not only secured our data but also streamlined our compliance processes.", image: "img/case-study-healthcare.jpg" },
    'tech-startup': { title: "Rapid-Growth Tech Startup", icon: "🚀", problem: "Required a scalable, secure-by-design infrastructure to support 10x user growth and protect valuable intellectual property without hindering rapid development cycles.", solution: "Embedded security into the DevOps lifecycle (DevSecOps), implemented robust cloud security posture management (CSPM), and provided on-demand security consultation for new product features. Automated security testing throughout the CI/CD pipeline.", results: [{value:"10x", label:"User Growth Supported Securely"}, {value:"<1hr", label:"Security Review for New Features"}, {value:"0", label:"Major Security Incidents During Growth"}, {value:"$2M", label:"Estimated Savings from Breach Avoidance"}], testimonial: "2R-AT was instrumental in our ability to scale rapidly and securely. Their DevSecOps approach is a game-changer for startups.", image: "img/case-study-startup.jpg" }
};
const featureDetails = {
    'ai-detection': { icon: '🤖', title: 'AI-Powered Threat Detection', subtitle: 'Intelligent defense against evolving cyber threats.', description: 'Our AI engine analyzes billions of data points in real-time to identify and predict malicious activities, including zero-day exploits and advanced persistent threats. It continuously learns and adapts to new attack vectors, providing proactive and intelligent security.', keyPoints: ['Behavioral Analysis', 'Anomaly Detection', 'Predictive Threat Modeling', 'Automated Threat Prioritization'], techStack: ['Python', 'TensorFlow', 'Keras', 'Spark MLlib', 'Elasticsearch'], stats: [{value: '99.9%', label: 'Detection Rate for Known Threats'}, {value: '75%', label: 'Reduction in False Positives'}, {value: '<1 sec', label: 'Average Detection Time'}]},
    'real-time-response': { icon: '⚡', title: 'Real-Time Automated Response', subtitle: 'Neutralize threats before they escalate.', description: 'Instantly react to security incidents with our automated response system. Pre-defined playbooks and customizable workflows ensure rapid containment and neutralization of threats, minimizing impact and freeing up your security team.', keyPoints: ['SOAR Integration', 'Customizable Playbooks', 'Automated Containment', 'Incident Forensics Trail'], techStack: ['Ansible', 'Python', 'Kafka', 'Serverless Functions', 'GraphQL'], stats: [{value: '<60 sec', label: 'Average Response Time'}, {value: '90%', label: 'Incidents Handled Autonomously'}, {value: '24/7', label: 'Continuous Operation'}]},
    'zero-trust': { icon: '🔐', title: 'Zero Trust Architecture', subtitle: 'Never trust, always verify, at every layer.', description: 'Implement a comprehensive Zero Trust model that secures your data, applications, and infrastructure. We enforce strict access controls, microsegmentation, and continuous verification for every user and device, regardless of location.', keyPoints: ['Microsegmentation', 'Identity & Access Management (IAM)', 'Multi-Factor Authentication (MFA)', 'Least Privilege Access'], techStack: ['Istio', 'SPIFFE/SPIRE', 'OAuth 2.0/OIDC', 'BeyondCorp Principles', 'Attribute-Based Access Control (ABAC)'], stats: [{value: '80%', label: 'Reduction in Lateral Movement'}, {value: '100%', label: 'MFA Enforcement'}, {value: 'Granular', label: 'Access Control Policies'}]},
    'threat-intelligence': { icon: '🌐', title: 'Global Threat Intelligence', subtitle: 'Stay ahead with proactive threat insights.', description: 'Leverage our vast network of global threat intelligence sources, including proprietary research, dark web monitoring, and industry partnerships. Receive actionable intelligence tailored to your organization\'s risk profile.', keyPoints: ['Actionable IoCs', 'Dark Web Monitoring', 'Threat Actor Profiling', 'Industry-Specific Alerts'], techStack: ['MISP', 'OpenCTI', 'YARA', 'SIEM Integration', 'Threat Intelligence Platforms (TIPs)'], stats: [{value: '1M+', label: 'New IoCs Daily'}, {value: '50+', label: 'Intelligence Feeds'}, {value: 'Real-time', label: 'Alerting System'}]},
    'predictive-analytics': { icon: '📈', title: 'Predictive Security Analytics', subtitle: 'Anticipate and prevent attacks before they happen.', description: 'Utilize advanced data modeling and machine learning to forecast potential security breaches and vulnerabilities. Our predictive analytics help you prioritize resources and implement proactive defenses against future attacks.', keyPoints: ['Risk Scoring', 'Vulnerability Prediction', 'Attack Surface Forecasting', 'Security Trend Analysis'], techStack: ['R', 'SciKit-Learn', 'Prophet', 'Jupyter Notebooks', 'Data Warehousing (BigQuery/Snowflake)'], stats: [{value: '30%', label: 'More Accurate Risk Prediction'}, {value: 'Proactive', label: 'Defense Strategies'}, {value: 'Data-driven', label: 'Security Investments'}]},
    'certifications': { icon: '🏆', title: 'Industry Certified & Compliant', subtitle: 'Security practices you can trust.', description: 'Our solutions are built upon industry-leading standards and best practices. We help your organization achieve and maintain compliance with major regulations like ISO 27001, SOC 2, NIST, GDPR, HIPAA, and PCI-DSS.', keyPoints: ['ISO 27001 Certified', 'SOC 2 Type II Compliant', 'NIST Cybersecurity Framework Alignment', 'GDPR & HIPAA Ready'], techStack: ['Compliance Automation Tools', 'Audit Logging Systems', 'Policy Management Platforms', 'GRC Tools'], stats: [{value: '100%', label: 'Audit Pass Rate for Clients'}, {value: 'Continuous', label: 'Compliance Monitoring'}, {value: 'Expert-led', label: 'Guidance & Support'}]}
};
const serviceDetails = {
    'cloud-security': { icon: '☁️', title: 'Cloud Security', subtitle: 'Comprehensive protection for your cloud infrastructure.', description: 'Secure your AWS, Azure, GCP, and hybrid cloud environments with our advanced cloud security solutions. We provide real-time monitoring, automated threat response, configuration management, and compliance assurance tailored to your specific cloud setup.', keyFeatures: ['Cloud Security Posture Management (CSPM)', 'Cloud Workload Protection Platform (CWPP)', 'Serverless Security', 'Container Security (Kubernetes, Docker)', 'Infrastructure as Code (IaC) Security', 'Cloud Native SIEM/SOAR Integration'], pricing: 'Custom Quote based on Cloud Footprint', relatedCaseStudy: 'tech-startup' },
    'penetration-testing': { icon: '🔓', title: 'Penetration Testing', subtitle: 'Identify vulnerabilities before attackers do.', description: 'Our elite ethical hackers simulate real-world attacks on your applications, networks, and systems. We provide detailed reports with actionable recommendations to remediate identified weaknesses and strengthen your defenses.', keyFeatures: ['Network (Internal/External) Pentesting', 'Web Application Pentesting (OWASP Top 10)', 'Mobile Application Pentesting (iOS/Android)', 'API Security Testing', 'Social Engineering Campaigns', 'Red Team / Blue Team Exercises'], pricing: 'Starting at $5,000 per Assessment', relatedCaseStudy: 'financial-institution' },
    'vulnerability-analysis': { icon: '🛡️', title: 'Vulnerability Analysis', subtitle: 'Proactive identification of security weaknesses.', description: 'Comprehensive security assessments using cutting-edge tools and expert methodologies to identify, classify, and prioritize vulnerabilities in your systems and applications. We help you understand your risk exposure and focus remediation efforts effectively.', keyFeatures: ['Automated Scanning & Manual Verification', 'Risk-Based Prioritization', 'False Positive Reduction', 'Continuous Vulnerability Monitoring', 'Remediation Guidance & Tracking', 'Compliance Reporting (PCI, HIPAA, etc.)'], pricing: 'Starting at $2,500 per Scan Cycle', relatedCaseStudy: 'healthcare-network' },
    'threat-hunting': { icon: '🎯', title: 'Threat Hunting', subtitle: 'Proactively uncover hidden threats in your environment.', description: 'Our expert threat hunters actively search for indicators of compromise (IoCs) and malicious activities that may have bypassed traditional security defenses. We use advanced analytics, threat intelligence, and hypothesis-driven investigations to find and neutralize APTs and zero-day exploits.', keyFeatures: ['Hypothesis-Driven Investigations', 'Endpoint Detection & Response (EDR) Analysis', 'Network Traffic Analysis (NTA)', 'Log Analysis & SIEM Correlation', 'Threat Intelligence Integration', 'Proactive IoC Sweeps'], pricing: 'Subscription-based or Retainer', relatedCaseStudy: 'tech-startup' },
    'grc-services': { icon: '📊', title: 'GRC Services', subtitle: 'Align security with your business objectives.', description: 'Achieve and maintain compliance with industry regulations and standards (e.g., ISO 27001, SOC 2, GDPR, HIPAA, PCI-DSS). We offer comprehensive Governance, Risk, and Compliance solutions, including gap analysis, policy development, risk assessments, and audit support.', keyFeatures: ['Compliance Gap Analysis', 'Security Policy Development', 'Risk Assessment & Management', 'Audit Preparation & Support', 'Vendor Risk Management', 'Security Awareness Training Integration'], pricing: 'Custom Quote based on Scope', relatedCaseStudy: 'financial-institution' },
    'security-auditing': { icon: '🔍', title: 'Security Auditing', subtitle: 'Independent verification of your security posture.', description: 'Thorough and independent security audits to assess the effectiveness of your controls and ensure compliance with internal policies and external regulations. Our certified auditors provide objective insights and recommendations for improvement.', keyFeatures: ['Internal & External Audits', 'Compliance Audits (ISO, SOC, etc.)', 'Security Control Assessments', 'Configuration Audits', 'Process & Policy Audits', 'Detailed Audit Reporting'], pricing: 'Starting at $7,000 per Audit', relatedCaseStudy: 'healthcare-network' }
};
const articleContent = {
    'zero-trust-2025': { title: "Zero Trust in 2025: Beyond the Buzzwords", date: "July 15, 2024", author: "Dr. Eve Archer", category: "Strategy", image: "img/blog-zero-trust.jpg", content: "<p>Zero Trust is no longer a futuristic concept but a foundational security strategy for modern enterprises...</p><h3>Key Principles Revisited</h3><ul><li>Verify Explicitly</li><li>Use Least Privilege Access</li><li>Assume Breach</li></ul><pre class='code-block'><code>function verifyAccess(user, resource) {\n  // Complex verification logic\n  return true;\n}</code></pre>" },
    'ransomware-tactics': { title: "Evolving Ransomware Tactics & Defenses", date: "June 28, 2024", author: "Marcus 'Glitch' Chen", category: "Threats", image: "img/blog-ransomware.jpg", content: "<p>Ransomware groups continue to innovate, employing double and triple extortion techniques...</p>" },
    'gdpr-ai': { title: "Navigating GDPR in the Age of AI", date: "May 10, 2024", author: "Lena Petrova, CIPP/E", category: "Compliance", image: "img/blog-gdpr-ai.jpg", content: "<p>Artificial Intelligence presents unique challenges for GDPR compliance, particularly concerning data subject rights and automated decision-making...</p>" }
};

// --- Core Authentication System (from login_js_content, enhanced) ---
class AuthSystem {
    constructor() {
        this.currentUser = JSON.parse(localStorage.getItem('currentUser'));
        this.users = JSON.parse(localStorage.getItem('users')) || [];

        this.protectedContentMap = {
            'dashboard': 'dashboard-container',
            'ctf-challenges': 'ctf-section' // Changed to overall section for overlay
        };
        // Call initializeUI via DOMContentLoaded to ensure elements are present
    }

    initializeUI() {
        this.updateUserInterface();
        this.addProtectedOverlays();
        document.querySelectorAll('a[href="#dashboard"], a[href="#ctf-challenges"]').forEach(link => {
            link.addEventListener('click', (e) => {
                // The main smooth scroll handler will now call auth.handleProtectedLinkClick
                // This specific listener might be redundant if the main one handles it.
                // For safety, keeping a direct call path if possible or relying on the global one.
            });
        });
    }

    showLogin() {
        const authModal = document.getElementById('authModal');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        if(authModal) authModal.classList.add('show');
        if(loginForm) loginForm.style.display = 'block';
        if(registerForm) registerForm.style.display = 'none';
    }

    showRegister() {
        const authModal = document.getElementById('authModal');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        if(authModal) authModal.classList.add('show');
        if(loginForm) loginForm.style.display = 'none';
        if(registerForm) registerForm.style.display = 'block';
    }

    closeAuthModal() {
        const authModal = document.getElementById('authModal');
        if(authModal) authModal.classList.remove('show');
    }

    switchToLogin() {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        if(loginForm) loginForm.style.display = 'block';
        if(registerForm) registerForm.style.display = 'none';
    }

    switchToRegister() {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        if(loginForm) loginForm.style.display = 'none';
        if(registerForm) registerForm.style.display = 'block';
    }

    handleLogin(event) {
        event.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        const foundUser = this.users.find(user => user.email === email && user.password === password);

        if (foundUser) {
            this.currentUser = { ...foundUser };
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
            this.updateUserInterface();
            this.removeProtectedOverlays();
            this.closeAuthModal();
            this.showWelcomeMessage();
        } else {
            alert('Invalid email or password.');
        }
    }

    handleRegister(event) {
        event.preventDefault();
        const name = document.getElementById('registerName').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
        const company = document.getElementById('registerCompany').value;

        if (this.users.find(user => user.email === email)) {
            alert('User with this email already exists.');
            return;
        }

        const newUser = {
            name, email, password, company,
            points: 50,
            avatar: name.charAt(0).toUpperCase(),
            stats: { ctfPoints: 0, challengesCompleted: 0 },
            achievements: []
        };
        this.users.push(newUser);
        localStorage.setItem('users', JSON.stringify(this.users));

        this.currentUser = { ...newUser };
        localStorage.setItem('currentUser', JSON.stringify(this.currentUser));

        this.updateUserInterface();
        this.removeProtectedOverlays();
        this.closeAuthModal();
        this.showWelcomeMessage("Registration successful! Welcome aboard!");
    }

    updateUserInterface() {
        const authNav = document.getElementById('auth-nav');
        const userNav = document.getElementById('user-nav');
        const userAvatarText = document.getElementById('user-avatar-text');
        const navUserName = document.getElementById('nav-user-name');
        const navUserPoints = document.getElementById('nav-user-points');

        if (!authNav || !userNav || !userAvatarText || !navUserName || !navUserPoints) return;

        if (this.currentUser) {
            authNav.style.display = 'none';
            userNav.style.display = 'block';
            userAvatarText.textContent = this.currentUser.avatar || 'U';
            navUserName.textContent = this.currentUser.name || 'User';
            navUserPoints.textContent = (this.currentUser.points || 0) + ' pts';
        } else {
            authNav.style.display = 'flex';
            userNav.style.display = 'none';
        }
    }

    updateUserStats(statsUpdate) {
        if (!this.currentUser) return;
        this.currentUser.stats = { ...this.currentUser.stats, ...statsUpdate };

        // If ctfPoints are part of the general points system
        if (statsUpdate.ctfPoints) {
            this.currentUser.points = (this.currentUser.points || 0) + statsUpdate.ctfPoints;
        }

        const userIndex = this.users.findIndex(u => u.email === this.currentUser.email);
        if (userIndex !== -1) {
            this.users[userIndex].stats = this.currentUser.stats;
            this.users[userIndex].points = this.currentUser.points; // Ensure total points are saved too
            localStorage.setItem('users', JSON.stringify(this.users));
        }
        localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
        this.updateUserInterface();
    }

    addAchievement(achievementTitle) {
        if (!this.currentUser) return;
        if (!this.currentUser.achievements) this.currentUser.achievements = [];
        if (!this.currentUser.achievements.includes(achievementTitle)) {
            this.currentUser.achievements.push(achievementTitle);

            const userIndex = this.users.findIndex(u => u.email === this.currentUser.email);
            if (userIndex !== -1) {
                this.users[userIndex].achievements = this.currentUser.achievements;
                localStorage.setItem('users', JSON.stringify(this.users));
            }
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
            this.showNotificationMessage(`🏆 Achievement Unlocked: ${achievementTitle}`, 'success');
        }
    }

    toggleUserMenu() {
        const dropdown = document.getElementById('user-dropdown');
        if (dropdown) dropdown.classList.toggle('show');
    }

    showUserDashboard() { this.toggleUserMenu(); alert('User Dashboard: Coming Soon!'); }
    showUserProfile() { this.toggleUserMenu(); alert('User Profile: Coming Soon!'); }
    showUserAchievements() {
        this.toggleUserMenu();
        if(this.currentUser && this.currentUser.achievements && this.currentUser.achievements.length > 0) {
            alert('Your Achievements:\n- ' + this.currentUser.achievements.join('\n- '));
        } else {
            alert('No achievements yet. Keep exploring!');
        }
    }
    showUserSettings() { this.toggleUserMenu(); alert('User Settings: Coming Soon!'); }

    logout() {
        this.currentUser = null;
        localStorage.removeItem('currentUser');
        this.updateUserInterface();
        const userDropdown = document.getElementById('user-dropdown');
        if (userDropdown) userDropdown.classList.remove('show');
        this.addProtectedOverlays();
        this.showLogoutMessage();
    }

    showWelcomeMessage(customMessage = '') {
        const message = customMessage || `Welcome back, ${this.currentUser.name}! 🔒`;
        this.showNotificationMessage(message, 'welcome');
    }

    showLogoutMessage() {
        this.showNotificationMessage('Logged out successfully! 👋', 'logout');
    }

    showNotificationMessage(message, type) {
        const notificationDiv = document.createElement('div');
        // Ensure this class is styled in CSS
        notificationDiv.className = `auth-toast ${type}`;
        notificationDiv.innerHTML = message;
        document.body.appendChild(notificationDiv);

        if (!document.getElementById('auth-toast-styles')) {
            const toastStyle = document.createElement('style');
            toastStyle.id = 'auth-toast-styles';
            toastStyle.textContent = `
                .auth-toast { position: fixed; top: 80px; right: 20px; padding: 1rem 2rem; border-radius: 10px; z-index: 10001; animation: slideInRightToast 0.5s ease, fadeOutToast 0.5s ease 2.5s forwards; color: var(--light); font-size: 0.9rem; }
                .auth-toast.welcome { background: linear-gradient(135deg, var(--primary), var(--secondary)); }
                .auth-toast.logout { background: rgba(16, 185, 129, 0.9); }
                .auth-toast.error { background: var(--danger); }
                .auth-toast.success { background: var(--success); } /* For achievements */
                @keyframes slideInRightToast { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
                @keyframes fadeOutToast { from { opacity: 1; } to { opacity: 0; transform: translateX(100%); } }
            `;
            document.head.appendChild(toastStyle);
        }

        setTimeout(() => notificationDiv.remove(), 3000);
    }

    isAuthenticated() {
        return this.currentUser !== null;
    }

    checkAuth(sectionId = null) {
        if (!this.isAuthenticated()) {
            this.showLogin();
            if (sectionId) {
                 this.showNotificationMessage(`Please log in to access the ${sectionId.replace('-', ' ')} section.`, 'error');
            }
            return false;
        }
        return true;
    }

    addProtectedOverlays() {
        if (this.isAuthenticated()) return;

        for (const sectionKey in this.protectedContentMap) {
            const contentId = this.protectedContentMap[sectionKey];
            const contentElement = document.getElementById(contentId);
            const overlayId = `overlay-${contentId}`;

            if (contentElement && !document.getElementById(overlayId)) {
                const overlay = document.createElement('div');
                overlay.id = overlayId;
                overlay.className = 'protected-overlay';
                overlay.innerHTML = `<p>🔒 This content is protected. <a href="#" onclick="event.preventDefault(); auth.showLogin();">Login</a> to access.</p>`;

                if(!document.getElementById('protected-overlay-styles')) {
                    const overlayStyle = document.createElement('style');
                    overlayStyle.id = 'protected-overlay-styles';
                    overlayStyle.textContent = `
                        .protected-overlay { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(10, 14, 39, 0.85); backdrop-filter: blur(5px); display: flex; align-items: center; justify-content: center; text-align: center; color: var(--light); z-index: 10; border-radius: inherit; }
                        .protected-overlay p { font-size: 1.2rem; padding: 20px; }
                        .protected-overlay a { color: var(--primary); text-decoration: underline; }
                    `;
                    document.head.appendChild(overlayStyle);
                }

                if (getComputedStyle(contentElement).position === 'static') {
                    contentElement.style.position = 'relative';
                }
                contentElement.appendChild(overlay);
            }
        }
    }

    removeProtectedOverlays() {
        if (!this.isAuthenticated()) return;

        for (const sectionKey in this.protectedContentMap) {
            const contentId = this.protectedContentMap[sectionKey];
            const overlay = document.getElementById(`overlay-${contentId}`);
            if (overlay) overlay.remove();
        }
    }

    handleProtectedLinkClick(sectionId) {
        if (this.checkAuth(sectionId)) {
            const targetElement = document.getElementById(sectionId);
            if (targetElement) {
                // Hide all main sections first
                document.querySelectorAll('main > section, .main-content-section').forEach(sec => {
                    if(sec.id !== 'home' && !sec.classList.contains('always-visible')) { // Keep home section as is or handle its display logic elsewhere
                         // sec.style.display = 'none'; // Decide if hiding all other sections is desired
                    }
                });
                // Show the target section
                targetElement.style.display = 'block'; // Or 'flex', etc.
                targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });

                if (sectionId === 'ctf-challenges') {
                    console.log("Accessing CTF Challenges page. Ensure challenges are interactive.");
                } else if (sectionId === 'dashboard') {
                    console.log("Accessing Dashboard. Ensure data is fresh.");
                     // Potentially call animateDashboard() again if it should refresh on each view
                }
            }
        }
    }
}
const auth = new AuthSystem();

// CTF Challenge System (from login_js_content, adapted)
const ctfChallengesData = {
    'web-app': { title: 'Corporate Data Breach Investigation', correctFlag: '2R-AT{SQL_1nj3ct10n_4nd_XSS_c0mb0_4tt4ck}', points: 1000, hints: [ { text: "Look for SQL injection in the login form - try using single quotes", cost: 50 }, { text: "The admin panel might have XSS vulnerabilities in the search function", cost: 100 }, { text: "Check the source code for hidden admin credentials in JavaScript comments", cost: 150 } ] },
    'network-forensics': { title: 'APT Network Infiltration Analysis', correctFlag: '2R-AT{C2_53rv3r_192.168.100.42_p0rt_8080_DN5_tunneling}', points: 800, hints: [ { text: "Focus on DNS queries that look like base64 encoded data", cost: 40 }, { text: "The C2 server uses port 8080 and disguises traffic as HTTP requests", cost: 80 }, { text: "Look for packets with unusual user-agent strings containing 'APT-Agent-v2.1'", cost: 120 } ] },
    'cryptography': { title: 'State-Sponsored Crypto Espionage', correctFlag: '2R-AT{SILVER_STORM_2025_power_grid_attack_feb_15}', points: 600, hints: [ { text: "The first part is Base64 encoded, the second part uses ROT13 cipher", cost: 30 }, { text: "Look for the operation codename in the decrypted message", cost: 60 }, { text: "Combine the decrypted attack details with the operation codename", cost: 90 } ] },
    'digital-forensics': { title: 'Insider Threat Investigation', correctFlag: '2R-AT{john_smith_usb_exfiltration_2025-01-20_encrypted_7zip}', points: 1200, hints: [ { text: "Check the Windows Event Logs for USB device insertion events", cost: 60 }, { text: "Look for large 7zip files in the user's temp directory and recycle bin", cost: 120 }, { text: "The suspect's name is in the laptop's user profile, combine with exfiltration method", cost: 180 } ] }
};
const ctfPrizesData = {
    1000: { rank: "🏆 EXPERT LEVEL", bonus: "You've earned a $500 Amazon gift card + priority consideration for our red team!"},
    800: { rank: "🥈 ADVANCED LEVEL", bonus: "You've earned a $300 Amazon gift card + access to our advanced training!"},
    600: { rank: "🥉 INTERMEDIATE LEVEL", bonus: "You've earned a $200 Amazon gift card + free certification voucher!"},
    400: { rank: "🎯 BEGINNER LEVEL", bonus: "You've earned a $100 Amazon gift card + training course access!"}
};
let usedHints = {};

function showHint(challengeId, hintNumber) {
    if (!auth.checkAuth('CTF Challenge Hint')) return;
    const challenge = ctfChallengesData[challengeId];
    if (!challenge || !challenge.hints || !challenge.hints[hintNumber-1]) return;
    const hint = challenge.hints[hintNumber - 1];
    if (!usedHints[challengeId]) usedHints[challengeId] = [];
    if (usedHints[challengeId].includes(hintNumber)) { auth.showNotificationMessage("You've already used this hint!", "error"); return; }

    const useHintConfirmed = confirm(`This hint will cost ${hint.cost} points. Continue?\n\nHint: ${hint.text}`);
    if (useHintConfirmed) {
        usedHints[challengeId].push(hintNumber);
        auth.updateUserStats({ ctfPoints: -hint.cost });
        auth.showNotificationMessage(`Hint revealed! You lost ${hint.cost} points.`, "logout"); // 'logout' style is green like success
    }
}

function submitFlag(challengeId) {
    if (!auth.checkAuth('CTF Challenge Submission')) return;
    const inputElement = document.getElementById(`flag-${challengeId}`);
    if(!inputElement) return;
    const submittedFlag = inputElement.value.trim();
    const challenge = ctfChallengesData[challengeId];
    if (!challenge) return;
    if (!submittedFlag) { auth.showNotificationMessage("Please enter a flag!", "error"); return; }

    let finalPoints = challenge.points;
    if (usedHints[challengeId]) {
        usedHints[challengeId].forEach(hintNum => { finalPoints -= challenge.hints[hintNum - 1].cost; });
    }

    if (submittedFlag === challenge.correctFlag) {
        auth.updateUserStats({ ctfPoints: finalPoints, challengesCompleted: (auth.currentUser.stats.challengesCompleted || 0) + 1 });
        auth.addAchievement(`Completed: ${challenge.title}`);
        showCtfSuccessResponse(challengeId, finalPoints, challenge.title);
        inputElement.value = ''; inputElement.disabled = true;
        const submitButton = inputElement.nextElementSibling; // Assuming button is next sibling
        if(submitButton) submitButton.disabled = true;
        createCelebrationEffect();
    } else {
        showCtfFailureResponse(submittedFlag, challengeId);
    }
}

function showCtfSuccessResponse(challengeId, points, challengeTitle) {
    let prizeInfo = ctfPrizesData[400];
    if (points >= 1000) prizeInfo = ctfPrizesData[1000];
    else if (points >= 800) prizeInfo = ctfPrizesData[800];
    else if (points >= 600) prizeInfo = ctfPrizesData[600];

    const successMessage = `🎊 FLAG CAPTURED! 🎊\n\nChallenge: ${challengeTitle}\nPoints Earned: +${points}\nTotal User Points: ${auth.currentUser.points}\nLevel: ${prizeInfo.rank}\n\n🎁 ${prizeInfo.bonus}\n\n📧 Prize details will be sent to your email.`;
    auth.showNotificationMessage(successMessage.replace(/\n/g, '<br>'), 'success'); // Use notification for consistency
}

function showCtfFailureResponse(submittedFlag, challengeId) {
    const responses = [ "🚫 Incorrect flag!", "❌ Not quite right. Try again.", "🔍 Close, but no cigar."];
    const randomResponse = responses[Math.floor(Math.random() * responses.length)];
    auth.showNotificationMessage(randomResponse, 'error');
    // const useHint = confirm(`${randomResponse}\n\nUse a hint? (-cost points)`); // Alert/confirm can be annoying
    // if (useHint) showCtfHintOptions(challengeId);
}

function showCtfHintOptions(challengeId) {
    if (!auth.checkAuth('CTF Hint Options')) return;
    const challenge = ctfChallengesData[challengeId];
    if (!challenge) return;
    let hintOptionsText = "Available hints:\n\n";
    challenge.hints.forEach((hint, index) => {
        const hintNum = index + 1;
        const alreadyUsed = usedHints[challengeId] && usedHints[challengeId].includes(hintNum);
        hintOptionsText += `${hintNum}. ${hint.text}${alreadyUsed ? " (Used)" : ` (-${hint.cost} pts)`}\n\n`;
    });
    const hintChoice = prompt(hintOptionsText + "Enter hint number (1-3) or 0 to cancel:");
    if (hintChoice && hintChoice !== "0" && !isNaN(parseInt(hintChoice))) {
        showHint(challengeId, parseInt(hintChoice));
    }
}

// --- UI Interaction functions for Detail Views (from comprehensive_js_content) ---
function showTrainingDetail(trainingId) {
    const detail = trainingDetails[trainingId];
    if (!detail) return;
    const contentElement = document.getElementById('training-detail-content'); // Assuming these IDs exist in HTML
    const detailSection = document.getElementById('training-detail');
    const mainSection = document.getElementById('training');
    if(!contentElement || !detailSection || !mainSection) { console.error("Training detail elements missing"); return; }

    contentElement.innerHTML = `
        <button onclick="closeTrainingDetail()" class="close-detail btn btn-secondary" style="margin-bottom:2rem;">← Back to Trainings</button>
        <div class="service-detail-header"> <div class="service-detail-icon">${detail.icon}</div> <h2 class="service-detail-title">${detail.title}</h2> <p style="font-size: 1.3rem; color: var(--gray);">${detail.subtitle}</p> </div>
        <div style="max-width: 800px; margin: 0 auto; text-align: center; margin-bottom: 3rem;"> <p style="font-size: 1.1rem; line-height: 1.8;">${detail.description}</p> </div>
        <div class="feature-stats"> <div class="feature-stat"> <span class="feature-stat-number">${detail.duration}</span> <span style="color: var(--gray);">Duration</span> </div> <div class="feature-stat"> <span class="feature-stat-number">${detail.level}</span> <span style="color: var(--gray);">Level</span> </div> <div class="feature-stat"> <span class="feature-stat-number">${detail.format}</span> <span style="color: var(--gray);">Format</span> </div> <div class="feature-stat"> <span class="feature-stat-number">✓</span> <span style="color: var(--gray);">Certification</span> </div> </div>
        <div class="service-detail-grid"> <div class="detail-card"> <h3 style="color: var(--primary); margin-bottom: 1.5rem;">Key Features</h3> <ul class="detail-features"> ${detail.features.map(f => `<li>${f}</li>`).join('')} </ul> </div> <div class="detail-card"> <h3 style="color: var(--primary); margin-bottom: 1.5rem;">Benefits</h3> ${detail.benefits.map(b => `<div style="margin-bottom: 1.5rem;"><h4 style="color: var(--light); margin-bottom: 0.5rem;">${b.title}</h4><p style="color: var(--gray);">${b.desc}</p></div>`).join('')} </div> </div>
        <div style="margin-top: 3rem;"> <h3 style="text-align: center; color: var(--primary); margin-bottom: 2rem;">Curriculum</h3> <div class="case-timeline"> ${detail.curriculum.map((m, i) => `<div class="timeline-item"><div class="timeline-icon">${i+1}</div><div class="timeline-content"><h4 style="color: var(--light); margin-bottom: 0.5rem;">${m.module} - ${m.duration}</h4><p style="color: var(--gray);">${m.desc}</p></div></div>`).join('')} </div> </div>
        <div class="service-pricing"> <h3 style="font-size: 2rem; margin-bottom: 1rem;">Investment</h3> <div class="price-tag">${detail.pricing}</div> <p style="color: var(--gray); margin-bottom: 1rem;">Certification: ${detail.certificationOffered}</p> <p style="color: var(--gray); margin-bottom: 2rem;">Group discounts available.</p> <button class="btn btn-primary" onclick="scrollToContactAndCloseDetails()">Enroll Now</button> <button class="btn btn-secondary" style="margin-left: 1rem;" onclick="downloadBrochure('${trainingId}')">Download Brochure</button> </div>`;
    mainSection.style.display = 'none'; detailSection.style.display = 'block';
    detailSection.scrollIntoView({ behavior: 'smooth' });
}
function closeTrainingDetail() {
    const detailSection = document.getElementById('training-detail');
    const mainSection = document.getElementById('training');
    if(detailSection) detailSection.style.display = 'none';
    if(mainSection) { mainSection.style.display = 'block'; mainSection.scrollIntoView({ behavior: 'smooth' }); }
}
function downloadBrochure(trainingId) { const t = trainingDetails[trainingId]; if(t) auth.showNotificationMessage(`Brochure for "${t.title}" will be sent.`, 'success'); }

function showServiceDetail(serviceId) { const detail = serviceDetails[serviceId]; if (!detail) return; console.log("Show service:", serviceId); auth.showNotificationMessage("Service Detail view for: " + (detail.title || serviceId) + " (Full view coming soon!)", "success"); }
function closeServiceDetail() { console.log("Close service detail"); /* Logic to hide detail and show main services */ }
function showCaseDetail(caseId) { const detail = caseStudyDetails[caseId]; if (!detail) return; console.log("Show case study:", caseId); auth.showNotificationMessage("Case Study Detail view for: " + (detail.title || caseId) + " (Full view coming soon!)", "success"); }
function closeCaseDetail() { console.log("Close case study detail"); /* Logic to hide detail */ }
function showFeatureDetail(featureId) { const detail = featureDetails[featureId]; if (!detail) return; console.log("Show feature:", featureId); auth.showNotificationMessage("Feature Detail view for: " + (detail.title || featureId) + " (Full view coming soon!)", "success"); }
function closeFeatureDetail() { console.log("Close feature detail"); /* Logic to hide detail */ }
function showArticle(articleId) { const detail = articleContent[articleId]; if (!detail) return; console.log("Show article:", articleId); auth.showNotificationMessage("Article view for: " + (detail.title || articleId) + " (Full view coming soon!)", "success"); }
function closeArticle() { console.log("Close article"); /* Logic to hide modal */ }


function scrollToContactAndCloseDetails() {
    ['service-detail', 'training-detail', 'feature-detail', 'case-detail'].forEach(id => {
        const el = document.getElementById(id);
        if (el && el.style.display === 'block') el.style.display = 'none';
    });
    const articleModal = document.getElementById('article-modal');
    if (articleModal && articleModal.style.display !== 'none') articleModal.style.display = 'none';

    // Show main sections again
    document.querySelectorAll('#professional-services, #training, #features, #case-studies').forEach(sec => {
        if(sec) sec.style.display = 'block'; // Or 'grid' etc. as per their default
    });

    setTimeout(() => {
        const contactSection = document.getElementById('contact');
        if (contactSection) contactSection.scrollIntoView({ behavior: 'smooth' });
    }, 100);
}


// --- General UI Enhancements ---
function createCelebrationEffect() { for (let i = 0; i < 50; i++) createConfetti(); }
function createConfetti() {
    const confetti = document.createElement('div');
    confetti.style.cssText = `position: fixed; left: ${Math.random()*window.innerWidth}px; top: -10px; width: ${Math.random()*8+6}px; height: ${Math.random()*8+6}px; background-color: ${['#FFD700','#FF6B6B','#4ECDC4','#45B7D1','#96CEB4'][Math.floor(Math.random()*5)]}; border-radius: 50%; pointer-events: none; z-index: 10000; transition: transform 3s linear, opacity 3s linear;`;
    document.body.appendChild(confetti);
    requestAnimationFrame(() => { confetti.style.transform = `translateY(${window.innerHeight+20}px) rotate(${Math.random()*360}deg)`; confetti.style.opacity = '0'; });
    setTimeout(() => confetti.remove(), 3000);
}

window.addEventListener('load', () => {
    setTimeout(() => {
        const loaderEl = document.getElementById('loader');
        if (loaderEl) { loaderEl.style.opacity = '0'; setTimeout(() => loaderEl.style.display = 'none', 500); }
    }, 1000);
    // DOMContentLoaded is better for JS that doesn't rely on images/css fully loaded
});

document.addEventListener('DOMContentLoaded', () => {
    auth.initializeUI(); // Initialize AuthSystem UI elements, event listeners, and overlays

    ['service-detail', 'training-detail', 'feature-detail', 'case-detail'].forEach(id => {
        const section = document.getElementById(id);
        if (section) section.style.display = 'none';
    });
    const articleModal = document.getElementById('article-modal');
    if(articleModal) articleModal.style.display = 'none';

    // Other initializations from login.js if they are not covered by auth.initializeUI()
    if (document.getElementById('particles')) setInterval(createParticle, 300);

    const statsSec = document.querySelector('.stats');
    if (statsSec) {
        new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => { if (entry.isIntersecting) { animateStats(); observer.unobserve(entry.target); } });
        }, { threshold: 0.5 }).observe(statsSec);
    }

    const dashSec = document.querySelector('.dashboard-section');
    if (dashSec) {
        new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => { if (entry.isIntersecting) { animateDashboard(); if(document.getElementById('threat-container')) setInterval(createThreatPoint, 1500); observer.unobserve(entry.target); } });
        }, { threshold: 0.5 }).observe(dashSec);
    }

    const termContentTyping = document.querySelector('.terminal-content .typing');
    if (termContentTyping) {
        new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.width='0'; entry.target.style.animation='none';
                    void entry.target.offsetWidth; entry.target.style.animation='';
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 }).observe(termContentTyping);
    }

    const animElements = document.querySelectorAll('.service-card, .training-card, .feature-item, .case-card');
    if (animElements.length > 0) {
        const elObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
                    setTimeout(() => { entry.target.style.opacity = '1'; entry.target.style.transform = 'translateY(0)'; }, index * 100);
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });
        animElements.forEach(el => { el.style.cssText = 'opacity:0;transform:translateY(20px);transition:opacity .6s ease,transform .6s ease'; elObserver.observe(el); });
    }
});


function createParticle() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * window.innerWidth + 'px';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.opacity = Math.random() * 0.5 + 0.1;
    particlesContainer.appendChild(particle);
    setTimeout(() => particle.remove(), 15000);
}


document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const targetId = this.getAttribute('href').substring(1);

        if (targetId === 'dashboard' || targetId === 'ctf-challenges') {
            auth.handleProtectedLinkClick(targetId);
        } else {
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                 // Hide other detail views if open
                ['service-detail', 'training-detail', 'feature-detail', 'case-detail'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el && el.id !== targetId + '-detail' && el.style.display !== 'none') el.style.display = 'none';
                });
                // Show relevant main section if a detail view is closed or another main link is clicked
                if (!targetId.includes('-detail')) { // e.g. if not "training-detail"
                    document.querySelectorAll('main > section, .main-content-section').forEach(s => {
                       if(s.id === targetId) s.style.display = 'block'; // or appropriate display type
                       // else if (s.id !== 'home') s.style.display = 'none'; // careful with this
                    });
                }
                targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
        const navLinksEl = document.querySelector('.nav-links.active');
        const mobileToggleEl = document.querySelector('.mobile-menu-toggle.active');
        if (navLinksEl && mobileToggleEl) { navLinksEl.classList.remove('active'); mobileToggleEl.classList.remove('active'); }
    });
});

window.addEventListener('scroll', () => {
    const navbar = document.getElementById('navbar');
    if (navbar) {
        navbar.style.background = window.scrollY > 50 ? 'rgba(5, 7, 20, 0.95)' : 'rgba(5, 7, 20, 0.9)';
        navbar.style.boxShadow = window.scrollY > 50 ? '0 5px 20px rgba(0, 0, 0, 0.5)' : 'none';
    }
});

const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
const navLinks = document.querySelector('.nav-links');
if (mobileMenuToggle && navLinks) {
    mobileMenuToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        mobileMenuToggle.classList.toggle('active');
    });
}

const contactForm = document.getElementById('contactForm');
if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const button = e.target.querySelector('button[type="submit"]');
        const originalText = button.textContent;
        button.textContent = 'Securing...'; button.disabled = true;
        setTimeout(() => {
            button.textContent = 'Sent ✓'; button.style.background = 'var(--success)';
            setTimeout(() => { button.textContent = originalText; button.disabled = false; button.style.background = ''; e.target.reset(); }, 3000);
        }, 2000);
    });
}

function animateStats() {
    document.querySelectorAll('.stat-number').forEach(stat => {
        const targetText = stat.textContent;
        const targetNumber = parseFloat(targetText.replace(/[^0-9.-]/g, '')); // Keep minus for <1min like cases
        if (isNaN(targetNumber) && !targetText.includes('<')) return; // Skip if not a number and not a special case like <1

        let finalDisplay = targetText;
        let numToAnimate = targetNumber;
        if(targetText.includes('<')) {
            numToAnimate = parseFloat(targetText.substring(1)); // Number after '<'
        }

        if (isNaN(numToAnimate)) return;

        let count = 0;
        const increment = numToAnimate / 50; // Animate in 50 steps
        const timer = setInterval(() => {
            count += increment;
            if (count >= numToAnimate) {
                stat.textContent = finalDisplay;
                clearInterval(timer);
            } else {
                let currentDisplay = Math.floor(count);
                if (targetText.includes('%')) currentDisplay += '%';
                if (targetText.includes('+')) currentDisplay += '+';
                // For '<X', we just let it reach X then set to '<X'
                stat.textContent = currentDisplay;
            }
        }, 30);
    });
}

function animateDashboard() {
    let threats = 0; const tb = document.getElementById('threats-blocked'); if(tb) setInterval(()=>tb.textContent=(threats+=Math.floor(Math.random()*10)+1).toLocaleString(),2e3);
    const am = document.getElementById('active-monitors'); if(am) setInterval(()=>am.textContent=Math.floor(Math.random()*50)+200,3e3);
    let data = 0; const da = document.getElementById('data-analyzed'); if(da) setInterval(()=>{data+=Math.random()*.5;da.textContent=data.toFixed(1)+' TB'},1500);
}

function createThreatPoint() {
    const container = document.getElementById('threat-container');
    if (!container) return;
    const point = document.createElement('div');
    point.className = 'threat-point';
    point.style.left = Math.random() * 90 + 5 + '%';
    point.style.top = Math.random() * 80 + 10 + '%';
    container.appendChild(point);
    setTimeout(() => point.remove(), 2000);
}

document.addEventListener('click', function(event) {
    const userSection = document.querySelector('.user-section');
    const dropdown = document.getElementById('user-dropdown');
    if (userSection && dropdown && !userSection.contains(event.target) && dropdown.classList.contains('show')) {
        auth.toggleUserMenu();
    }
});
const authModalElement = document.getElementById('authModal');
if (authModalElement) {
    authModalElement.addEventListener('click', function(event) {
        if (event.target === this) {
            auth.closeAuthModal();
        }
    });
}

// Expose functions to global scope for HTML onclicks
window.showLogin = () => auth.showLogin();
window.showRegister = () => auth.showRegister();
window.closeAuthModal = () => auth.closeAuthModal();
window.switchToLogin = () => auth.switchToLogin();
window.switchToRegister = () => auth.switchToRegister();
window.handleLogin = (event) => auth.handleLogin(event);
window.handleRegister = (event) => auth.handleRegister(event);
window.toggleUserMenu = () => auth.toggleUserMenu();
window.showUserDashboard = () => auth.showUserDashboard();
window.showUserProfile = () => auth.showUserProfile();
window.showUserAchievements = () => auth.showUserAchievements();
window.showUserSettings = () => auth.showUserSettings();
window.logout = () => auth.logout();
window.showNotifications = () => { if(auth.checkAuth('Notifications')) auth.showNotificationMessage('Notification panel coming soon!', 'success');};

window.showHint = showHint;
window.submitFlag = submitFlag;

window.showTrainingDetail = showTrainingDetail;
window.closeTrainingDetail = closeTrainingDetail;
window.downloadBrochure = downloadBrochure;
window.showServiceDetail = showServiceDetail;
window.closeServiceDetail = closeServiceDetail;
window.showCaseDetail = showCaseDetail;
window.closeCaseDetail = closeCaseDetail;
window.showFeatureDetail = showFeatureDetail;
window.closeFeatureDetail = closeFeatureDetail;
window.showArticle = showArticle;
window.closeArticle = closeArticle;
window.scrollToContactAndCloseDetails = scrollToContactAndCloseDetails;

// --- End of Merged JavaScript ---
