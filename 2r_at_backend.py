#!/usr/bin/env python3
"""
2R-AT Cybersecurity Platform - Backend API
Advanced vulnerability scanning platform with Nuclei integration
"""

import os
import json
import sqlite3
import subprocess
import uuid
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import redis
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    DATABASE_PATH = '/var/lib/2r-at/scanner.db'
    REDIS_URL = 'redis://localhost:6379/0'
    NUCLEI_PATH = '/usr/local/bin/nuclei'
    SCAN_RESULTS_DIR = '/var/www/html/scan-results'
    LOG_DIR = '/var/log/2r-at'
    MAX_CONCURRENT_SCANS = 5
    RATE_LIMIT_DEFAULT = "100 per hour"

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
cors = CORS(app)
jwt = JWTManager(app)
redis_client = redis.from_url(Config.REDIS_URL)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT_DEFAULT]
)

# Logging setup
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{Config.LOG_DIR}/scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database helper class
class DatabaseManager:
    def __init__(self):
        self.db_path = Config.DATABASE_PATH
        
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def execute_query(self, query, params=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.fetchall()
    
    def get_user_by_email(self, email):
        query = "SELECT * FROM users WHERE email = ?"
        result = self.execute_query(query, (email,))
        return dict(result[0]) if result else None
    
    def create_user(self, user_data):
        query = """
        INSERT INTO users (id, email, name, password_hash, company, role, plan)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        user_id = str(uuid.uuid4())
        self.execute_query(query, (
            user_id, user_data['email'], user_data['name'],
            user_data['password_hash'], user_data.get('company', ''),
            user_data.get('role', 'user'), user_data.get('plan', 'basic')
        ))
        return user_id
    
    def create_scan(self, scan_data):
        query = """
        INSERT INTO scans (id, user_id, target, scan_name, status)
        VALUES (?, ?, ?, ?, ?)
        """
        scan_id = str(uuid.uuid4())
        self.execute_query(query, (
            scan_id, scan_data['user_id'], scan_data['target'],
            scan_data.get('scan_name', ''), 'queued'
        ))
        return scan_id
    
    def update_scan_status(self, scan_id, status, result_data=None, error_message=None):
        if status == 'running':
            query = "UPDATE scans SET status = ?, started_at = ? WHERE id = ?"
            params = (status, datetime.now(), scan_id)
        elif status == 'completed':
            query = "UPDATE scans SET status = ?, completed_at = ?, result_data = ? WHERE id = ?"
            params = (status, datetime.now(), result_data, scan_id)
        elif status == 'failed':
            query = "UPDATE scans SET status = ?, completed_at = ?, error_message = ? WHERE id = ?"
            params = (status, datetime.now(), error_message, scan_id)
        else:
            query = "UPDATE scans SET status = ? WHERE id = ?"
            params = (status, scan_id)
        
        self.execute_query(query, params)
    
    def get_user_scans(self, user_id, limit=50):
        query = """
        SELECT * FROM scans WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT ?
        """
        return [dict(row) for row in self.execute_query(query, (user_id, limit))]
    
    def get_scan_by_id(self, scan_id):
        query = "SELECT * FROM scans WHERE id = ?"
        result = self.execute_query(query, (scan_id,))
        return dict(result[0]) if result else None

# Initialize database manager
db = DatabaseManager()

# Nuclei Scanner class
class NucleiScanner:
    def __init__(self):
        self.nuclei_path = Config.NUCLEI_PATH
        self.results_dir = Config.SCAN_RESULTS_DIR
        
    def run_scan(self, target, scan_id, scan_options=None):
        """Run Nuclei scan against target"""
        try:
            # Ensure results directory exists
            os.makedirs(self.results_dir, exist_ok=True)
            
            # Prepare output files
            json_output = f"{self.results_dir}/{scan_id}.json"
            html_output = f"{self.results_dir}/{scan_id}.html"
            
            # Build nuclei command
            cmd = [
                self.nuclei_path,
                '-target', target,
                '-json-export', json_output,
                '-me', html_output,
                '-stats',
                '-silent'
            ]
            
            # Add scan options if provided
            if scan_options:
                if scan_options.get('severity'):
                    cmd.extend(['-severity', scan_options['severity']])
                if scan_options.get('tags'):
                    cmd.extend(['-tags', scan_options['tags']])
                if scan_options.get('templates'):
                    cmd.extend(['-t', scan_options['templates']])
            
            logger.info(f"Starting scan {scan_id} for target {target}")
            
            # Update scan status to running
            db.update_scan_status(scan_id, 'running')
            
            # Execute nuclei scan
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Process results
            if process.returncode == 0:
                # Read results
                results = self._process_results(json_output)
                
                # Update scan with results
                db.update_scan_status(scan_id, 'completed', json.dumps(results))
                
                logger.info(f"Scan {scan_id} completed successfully")
                return {'status': 'success', 'results': results}
            else:
                error_msg = process.stderr or "Scan failed with unknown error"
                db.update_scan_status(scan_id, 'failed', error_message=error_msg)
                logger.error(f"Scan {scan_id} failed: {error_msg}")
                return {'status': 'error', 'message': error_msg}
                
        except subprocess.TimeoutExpired:
            error_msg = "Scan timeout exceeded"
            db.update_scan_status(scan_id, 'failed', error_message=error_msg)
            logger.error(f"Scan {scan_id} timed out")
            return {'status': 'error', 'message': error_msg}
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            db.update_scan_status(scan_id, 'failed', error_message=error_msg)
            logger.error(f"Scan {scan_id} error: {str(e)}")
            return {'status': 'error', 'message': error_msg}
    
    def _process_results(self, json_file):
        """Process nuclei JSON results"""
        results = {
            'vulnerabilities': [],
            'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }
        
        try:
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln = json.loads(line)
                            results['vulnerabilities'].append(vuln)
                            
                            # Update summary
                            severity = vuln.get('info', {}).get('severity', 'info').lower()
                            if severity in results['summary']:
                                results['summary'][severity] += 1
                            results['summary']['total'] += 1
        except Exception as e:
            logger.error(f"Error processing results: {str(e)}")
        
        return results

# Initialize scanner
scanner = NucleiScanner()

# Authentication decorator
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = db.execute_query("SELECT role FROM users WHERE id = ?", (current_user_id,))
        if not user or user[0]['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# API Routes

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database
        db.execute_query("SELECT 1")
        
        # Check Redis
        redis_client.ping()
        
        # Check Nuclei
        nuclei_version = subprocess.run([Config.NUCLEI_PATH, '-version'], 
                                      capture_output=True, text=True)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'database': 'online',
                'redis': 'online',
                'nuclei': 'online' if nuclei_version.returncode == 0 else 'offline'
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 503

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """User registration"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['email', 'name', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if user exists
        if db.get_user_by_email(data['email']):
            return jsonify({'error': 'User already exists'}), 409
        
        # Create user
        user_data = {
            'email': data['email'],
            'name': data['name'],
            'password_hash': generate_password_hash(data['password']),
            'company': data.get('company', ''),
            'role': 'user',  # Default role
            'plan': data.get('plan', 'basic')
        }
        
        user_id = db.create_user(user_data)
        
        # Create access token
        access_token = create_access_token(identity=user_id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'user': {
                'id': user_id,
                'email': data['email'],
                'name': data['name'],
                'role': 'user'
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User login"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        # Get user
        user = db.get_user_by_email(data['email'])
        if not user or not check_password_hash(user['password_hash'], data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user['is_active']:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Update last login
        db.execute_query("UPDATE users SET last_login = ? WHERE id = ?", 
                        (datetime.now(), user['id']))
        
        # Create access token
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'role': user['role'],
                'plan': user['plan']
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/scans', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def create_scan():
    """Create new vulnerability scan"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('target'):
            return jsonify({'error': 'Target is required'}), 400
        
        # Check user quota
        user = db.execute_query("SELECT scan_quota, scans_used FROM users WHERE id = ?", 
                               (current_user_id,))[0]
        
        if user['scans_used'] >= user['scan_quota']:
            return jsonify({'error': 'Scan quota exceeded'}), 429
        
        # Create scan record
        scan_data = {
            'user_id': current_user_id,
            'target': data['target'],
            'scan_name': data.get('scan_name', f"Scan of {data['target']}")
        }
        
        scan_id = db.create_scan(scan_data)
        
        # Queue scan for processing (in a real implementation, this would use Celery or similar)
        # For now, we'll run it synchronously (not recommended for production)
        scan_options = data.get('options', {})
        
        # Update user scan count
        db.execute_query("UPDATE users SET scans_used = scans_used + 1 WHERE id = ?", 
                        (current_user_id,))
        
        # Start scan in background (simplified - use proper task queue in production)
        import threading
        scan_thread = threading.Thread(
            target=scanner.run_scan, 
            args=(data['target'], scan_id, scan_options)
        )
        scan_thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'queued',
            'message': 'Scan started successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Scan creation error: {str(e)}")
        return jsonify({'error': 'Failed to create scan'}), 500

@app.route('/api/scans', methods=['GET'])
@jwt_required()
def get_scans():
    """Get user's scans"""
    try:
        current_user_id = get_jwt_identity()
        scans = db.get_user_scans(current_user_id)
        
        # Process scan data
        for scan in scans:
            if scan['result_data']:
                try:
                    scan['results'] = json.loads(scan['result_data'])
                except:
                    scan['results'] = None
            scan.pop('result_data', None)  # Remove raw JSON from response
        
        return jsonify({'scans': scans})
        
    except Exception as e:
        logger.error(f"Get scans error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scans'}), 500

@app.route('/api/scans/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    """Get specific scan details"""
    try:
        current_user_id = get_jwt_identity()
        scan = db.get_scan_by_id(scan_id)
        
        if not scan or scan['user_id'] != current_user_id:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Process results
        if scan['result_data']:
            try:
                scan['results'] = json.loads(scan['result_data'])
            except:
                scan['results'] = None
        
        scan.pop('result_data', None)
        
        return jsonify({'scan': scan})
        
    except Exception as e:
        logger.error(f"Get scan error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scan'}), 500

@app.route('/api/scans/<scan_id>/report', methods=['GET'])
@jwt_required()
def get_scan_report(scan_id):
    """Download scan report"""
    try:
        current_user_id = get_jwt_identity()
        scan = db.get_scan_by_id(scan_id)
        
        if not scan or scan['user_id'] != current_user_id:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if HTML report exists
        html_report = f"{Config.SCAN_RESULTS_DIR}/{scan_id}.html"
        if os.path.exists(html_report):
            return send_file(html_report, as_attachment=True, 
                           download_name=f"scan_report_{scan_id}.html")
        else:
            return jsonify({'error': 'Report not available'}), 404
            
    except Exception as e:
        logger.error(f"Get report error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve report'}), 500

@app.route('/api/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """Get user statistics"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get scan statistics
        stats_query = """
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_scans,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans
        FROM scans WHERE user_id = ?
        """
        
        stats = dict(db.execute_query(stats_query, (current_user_id,))[0])
        
        # Get user quota info
        user_query = "SELECT scan_quota, scans_used, plan FROM users WHERE id = ?"
        user_info = dict(db.execute_query(user_query, (current_user_id,))[0])
        
        return jsonify({
            'scans': stats,
            'quota': {
                'limit': user_info['scan_quota'],
                'used': user_info['scans_used'],
                'remaining': user_info['scan_quota'] - user_info['scans_used']
            },
            'plan': user_info['plan']
        })
        
    except Exception as e:
        logger.error(f"Get stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_all_users():
    """Admin: Get all users"""
    try:
        users = db.execute_query("""
            SELECT id, email, name, company, role, plan, created_at, 
                   last_login, is_active, scan_quota, scans_used
            FROM users ORDER BY created_at DESC
        """)
        
        return jsonify({'users': [dict(user) for user in users]})
        
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve users'}), 500

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """Admin: Get platform statistics"""
    try:
        # Platform stats
        platform_stats = {
            'total_users': db.execute_query("SELECT COUNT(*) as count FROM users")[0]['count'],
            'active_users': db.execute_query("SELECT COUNT(*) as count FROM users WHERE is_active = 1")[0]['count'],
            'total_scans': db.execute_query("SELECT COUNT(*) as count FROM scans")[0]['count'],
            'completed_scans': db.execute_query("SELECT COUNT(*) as count FROM scans WHERE status = 'completed'")[0]['count'],
            'running_scans': db.execute_query("SELECT COUNT(*) as count FROM scans WHERE status = 'running'")[0]['count']
        }
        
        return jsonify({'stats': platform_stats})
        
    except Exception as e:
        logger.error(f"Get admin stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e)}), 429

# Initialize admin user on startup
def create_admin_user():
    """Create default admin user if it doesn't exist"""
    try:
        admin_email = "admin@2r-at.com"
        if not db.get_user_by_email(admin_email):
            admin_data = {
                'email': admin_email,
                'name': 'System Administrator',
                'password_hash': generate_password_hash('admin123'),
                'company': '2R-AT Security',
                'role': 'admin',
                'plan': 'enterprise'
            }
            user_id = db.create_user(admin_data)
            logger.info(f"Created admin user: {admin_email}")
            return user_id
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")

if __name__ == '__main__':
    # Create admin user on startup
    create_admin_user()
    
    # Run development server
    app.run(host='127.0.0.1', port=5000, debug=False)
