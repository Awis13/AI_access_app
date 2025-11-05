#!/usr/bin/env python3
"""
Flask server for generating bcrypt hashes and extracting user info with AI.

The original internal tool required Keycloak SSO. For the public demo we keep
the same routes but default to a lightweight sessionless "demo" mode. Setting
AUTH_MODE=oidc alongside the required Keycloak environment variables re-enables
the enterprise flow.
"""

from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, g
from flask_cors import CORS
import bcrypt
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional
from functools import wraps
from authlib.integrations.flask_client import OAuth
import logging
import re
import time
from logging.handlers import RotatingFileHandler

class SensitiveDataFilter(logging.Filter):
    """Filter to mask password hashes in log messages"""

    def __init__(self):
        super().__init__()
        # Patterns for password hashes that should be masked
        self.sensitive_patterns = [
            # Bcrypt password hashes (format: $2a/b/y$rounds$salt$hash)
            (r'\$2[aby]\$[0-9]{1,2}\$[A-Za-z0-9./]{53}', '[PASSWORD_HASH_MASKED]'),
            # SHA-256/512 password hashes (format: $5$ or $6$)
            (r'\$[56]\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}', '[PASSWORD_HASH_MASKED]'),
            # MD5 password hashes (format: $1$)
            (r'\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}', '[PASSWORD_HASH_MASKED]'),
            # Generic password hash patterns in VALUES clauses
            (r"VALUES\s*\(\s*[\'\"]\$[0-9a-zA-Z./]+\$[\'\"]", "VALUES('[PASSWORD_HASH_MASKED]'"),
            # Password hash in SET clauses
            (r"SET\s+password\s*=\s*[\'\"]\$[0-9a-zA-Z./]+\$[\'\"]", "SET password='[PASSWORD_HASH_MASKED]'"),
        ]

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            # Apply all masking patterns
            masked_msg = record.msg
            for pattern, replacement in self.sensitive_patterns:
                masked_msg = re.sub(pattern, replacement, masked_msg, flags=re.IGNORECASE)

            # Also check formatted message if args exist
            if record.args:
                try:
                    formatted_msg = record.getMessage()
                    for pattern, replacement in self.sensitive_patterns:
                        formatted_msg = re.sub(pattern, replacement, formatted_msg, flags=re.IGNORECASE)
                    record.msg = formatted_msg
                    record.args = None  # Clear args since we've formatted it
                except:
                    pass  # If formatting fails, use original masking

            record.msg = masked_msg

        return True

app = Flask(__name__)
CORS(app)

# Configure logging with proper rotation
from config import LOG_FILE, LOG_LEVEL
log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

# Create logs directory if it doesn't exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Use TimedRotatingFileHandler for daily rotation with size-based rotation as backup
from logging.handlers import TimedRotatingFileHandler
handler = TimedRotatingFileHandler(
    LOG_FILE,
    when='midnight',  # Rotate at midnight
    interval=1,       # Every 1 interval (day)
    backupCount=30    # Keep 30 days of logs
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))

# Also add a size-based rotating handler as backup (10MB max)
size_handler = RotatingFileHandler(
    LOG_FILE + '.size',  # Separate file for size-based rotation
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5          # Keep 5 backup files
)
size_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))

# Create and add sensitive data filter to both handlers
sensitive_filter = SensitiveDataFilter()
handler.addFilter(sensitive_filter)
size_handler.addFilter(sensitive_filter)

# Also add filter to root logger to catch all log messages
root_logger = logging.getLogger()
root_logger.addFilter(sensitive_filter)
root_logger.setLevel(log_level)

# Add both handlers
app.logger.addHandler(handler)
app.logger.addHandler(size_handler)
app.logger.setLevel(log_level)

# Configure Flask session / authentication helpers
from config import (
    SECRET_KEY,
    AUTH_MODE,
    OIDC_ENABLED,
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET,
    OIDC_CONFIG,
    DEMO_USER,
)

app.secret_key = SECRET_KEY

oauth = OAuth(app) if OIDC_ENABLED else None

if OIDC_ENABLED and oauth:
    oauth.register(
        "keycloak",
        client_id=KEYCLOAK_CLIENT_ID,
        client_secret=KEYCLOAK_CLIENT_SECRET,
        server_metadata_url=OIDC_CONFIG["server_metadata_url"],
        client_kwargs={
            "scope": "openid profile email roles"
        },
    )

# Authentication helpers
def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not OIDC_ENABLED:
            # Demo mode: ensure a predictable session user for downstream code
            session.setdefault('user', DEMO_USER)
            return f(*args, **kwargs)
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current authenticated user from session"""
    if not OIDC_ENABLED:
        return session.get('user') or DEMO_USER
    return session.get('user')

def has_role(role_name):
    """Check if current user has specific role"""
    user = get_current_user()
    if not user:
        return False
    roles = user.get('roles', [])
    return role_name in roles

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not OIDC_ENABLED:
            # Demo mode treats the configured DEMO_USER as an admin
            return f(*args, **kwargs)
        if not has_role('admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Database connection (supports multi-env)
from config import APPS, DEFAULT_APP

def _resolve_db_cfg(app_key: Optional[str], env_key: Optional[str]) -> Optional[dict]:
    # Try explicit app/env from APPS
    if app_key:
        app_key_u = app_key.strip().upper()
        app_cfg = APPS.get(app_key_u)
        if app_cfg:
            dbs = app_cfg.get('databases', {})
            if env_key:
                env_u = env_key.strip().upper()
                if env_u in dbs:
                    return dbs[env_u]
            # fallback to app default env
            def_env = (app_cfg.get('default_env') or '').upper()
            if def_env and def_env in dbs:
                return dbs[def_env]
            # any first DB
            if dbs:
                return dbs[next(iter(dbs))]

    # Global default app fallback
    app_cfg = APPS.get(DEFAULT_APP)
    if app_cfg:
        dbs = app_cfg.get('databases', {})
        def_env = (app_cfg.get('default_env') or '').upper()
        if def_env and def_env in dbs:
            return dbs[def_env]
        if dbs:
            return dbs[next(iter(dbs))]
    return None

def get_db_connection(app_key: Optional[str] = None, env_key: Optional[str] = None):
    cfg = _resolve_db_cfg(app_key, env_key)
    if not cfg:
        raise RuntimeError('No database configuration found')
    required = ['host', 'database', 'user', 'password']
    for k in required:
        if k not in cfg:
            raise RuntimeError(f'Missing DB config key: {k}')
    return psycopg2.connect(
        dbname=cfg['database'],
        user=cfg['user'],
        password=cfg['password'],
        host=cfg['host'],
        port=cfg.get('port', 5432),
        cursor_factory=RealDictCursor,
    )

# Import functions from our scripts
import sys
sys.path.append('.')
from generate_access_queries import generate_password_hash
from extract_user_info import extract_with_ollama

# Authentication routes
@app.route('/login')
def login():
    """Initiate Keycloak OIDC login"""
    if not OIDC_ENABLED:
        session['user'] = DEMO_USER
        session['token'] = None
        return redirect(url_for('index'))
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    """Handle Keycloak OIDC callback"""
    if not OIDC_ENABLED:
        return jsonify({'error': 'Authentication not available in demo mode'}), 400
    try:
        token = oauth.keycloak.authorize_access_token()
        userinfo = token.get('userinfo')
        
        if userinfo:
            # Extract user information
            user_data = {
                'id': userinfo.get('sub'),
                'email': userinfo.get('email'),
                'name': userinfo.get('name'),
                'preferred_username': userinfo.get('preferred_username'),
                'roles': []
            }
            
            # Extract roles from token
            if 'access_token' in token:
                import jwt
                # Decode JWT without verification for role extraction
                # In production, you should verify the JWT properly
                try:
                    decoded = jwt.decode(token['access_token'], options={"verify_signature": False})
                    realm_access = decoded.get('realm_access', {})
                    user_data['roles'] = realm_access.get('roles', [])
                    
                    # Also check resource access for client-specific roles
                    resource_access = decoded.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {})
                    client_roles = resource_access.get('roles', [])
                    user_data['roles'].extend(client_roles)
                except Exception as e:
                    app.logger.error(f"Error extracting roles: {e}")
            
            # Store user in session
            session['user'] = user_data
            session['token'] = token
            
            app.logger.info(f"User logged in: {user_data['email']} with roles: {user_data['roles']}")
            return redirect(url_for('index'))
        else:
            return jsonify({'error': 'Failed to get user info'}), 400
    except Exception as e:
        app.logger.error(f"Auth callback error: {e}")
        return jsonify({'error': 'Authentication failed'}), 400

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    if not OIDC_ENABLED:
        session.clear()
        return redirect(url_for('index'))
    user = get_current_user()
    if user:
        app.logger.info(f"User logged out: {user.get('email')}")
    
    # Clear session
    session.clear()
    
    # Redirect to Keycloak logout endpoint
    keycloak_logout_url = f"{OIDC_CONFIG['issuer']}/protocol/openid-connect/logout"
    post_logout_redirect = url_for('index', _external=True)
    logout_url = (
        f"{keycloak_logout_url}"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&post_logout_redirect_uri={post_logout_redirect}"
    )
    
    return redirect(logout_url)

@app.route('/api/user')
@login_required
def get_user_info():
    """Get current user information"""
    user = get_current_user()
    if user:
        # Don't return sensitive token information
        safe_user = {
            'id': user.get('id'),
            'email': user.get('email'),
            'name': user.get('name'),
            'preferred_username': user.get('preferred_username'),
            'roles': user.get('roles', [])
        }
        return jsonify(safe_user)
    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/')
def index():
    # Authentication is ALWAYS required
    if not OIDC_ENABLED:
        session.setdefault('user', DEMO_USER)
    elif 'user' not in session:
        return redirect(url_for('login'))

    return send_from_directory('.', 'index_with_extraction.html')

@app.route('/api/config', methods=['GET'])
@login_required
def get_config():
    """Expose minimal UI config: list of apps and their environments (no URLs)."""
    apps = []
    for key, cfg in APPS.items():
        envs = list((cfg.get('databases') or {}).keys())
        apps.append({
            "key": key,
            "label": cfg.get('label', key),
            "environments": envs,
            "defaultEnv": cfg.get('default_env')
        })
    return jsonify({
        "defaultApp": DEFAULT_APP,
        "apps": apps,
        "authMode": "oidc" if OIDC_ENABLED else "demo"
    })

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)

@app.route('/hash', methods=['POST'])
@login_required
def hash_password():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({'error': 'Password required'}), 400
    
    password = data['password']
    hash_result = generate_password_hash(password)
    
    return jsonify({'hash': hash_result})

@app.route('/api/extract', methods=['POST'])
@login_required
def extract_user():
    """Extract user information from text using AI"""
    data = request.json
    if not data or 'text' not in data:
        return jsonify({'error': 'Text required'}), 400
    
    text = data['text']
    start_time = time.monotonic()
    request_id = f"extract-{int(start_time * 1000)}"

    app.logger.debug(
        "[%s] Incoming extraction request | length=%s preview=%s",
        request_id,
        len(text),
        text[:120].replace('\n', ' '),
    )

    try:
        result = extract_with_ollama(text)
        app.logger.debug("[%s] Ollama extractor result: %s", request_id, result)

        if result:
            # Convert to dict if it's a Pydantic model
            if hasattr(result, 'dict'):
                result = result.dict()
            elapsed = (time.monotonic() - start_time) * 1000
            app.logger.info("[%s] Extraction complete via Ollama in %.2f ms", request_id, elapsed)
            return jsonify(result)
        else:
            app.logger.warning("[%s] Ollama returned None, trying regex fallback", request_id)
            from extract_user_info import extract_with_regex
            result = extract_with_regex(text)
            elapsed = (time.monotonic() - start_time) * 1000
            app.logger.info("[%s] Extraction fallback result in %.2f ms", request_id, elapsed)
            app.logger.debug("[%s] Regex result: %s", request_id, result)
            return jsonify(result)
    except Exception as e:
        elapsed = (time.monotonic() - start_time) * 1000
        app.logger.exception("[%s] Extraction error after %.2f ms", request_id, elapsed)
        return jsonify({'error': str(e)}), 500

@app.route('/api/db/test', methods=['GET'])
@login_required
def test_database():
    """Test database connection and show users"""
    app_key = request.args.get('app')
    env_key = request.args.get('env')

    # First, test database connectivity
    try:
        conn = get_db_connection(app_key, env_key)
        # Test the connection with a simple query
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
    except Exception as e:
        app_name = app_key or DEFAULT_APP
        env_name = env_key or 'DEFAULT'
        return jsonify({
            'status': 'error',
            'message': f'Database not available: Cannot connect to {app_name} {env_name} database. Please ensure the database service is running.',
            'error_type': 'connection_error'
        }), 503

    try:
        conn = get_db_connection(app_key, env_key)
        cur = conn.cursor()
        cur.execute('SELECT id, login, name, email, enabled FROM "user" ORDER BY id')
        users = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            'status': 'success',
            'message': 'Database connection OK',
            'app': (app_key or DEFAULT_APP),
            'env': (env_key or 'DEFAULT'),
            'users': [dict(user) for user in users]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database query error: {e}'
        }), 500

@app.route('/api/db/execute', methods=['POST'])
@login_required
def execute_query():
    """Execute SQL query and return created user data"""
    data = request.json
    if not data or 'query' not in data:
        return jsonify({'error': 'SQL query required'}), 400
    
    query = data['query']
    app_key = data.get('app') if isinstance(data, dict) else None
    env_key = data.get('env') if isinstance(data, dict) else None
    user = get_current_user()
    user_email = user.get('email') if user else 'unknown'
    
    try:
        conn = get_db_connection(app_key, env_key)
        cur = conn.cursor()
        
        # Split multiple queries and execute them
        queries = [q.strip() for q in query.split(';') if q.strip()]
        results = []
        created_user = None
        
        db_cfg_for_log = _resolve_db_cfg(app_key, env_key) or {}
        # Log query execution with connection details (passwords will be masked by our filter)
        log_msg = (
            f"User '{user_email}' executing query on "
            f"app='{app_key}' env='{env_key}' "
            f"host='{db_cfg_for_log.get('host')}' db='{db_cfg_for_log.get('database')}'. "
            f"Query: {query}"
        )
        app.logger.info(log_msg)
        
        for q in queries:
            cur.execute(q)
            if q.upper().startswith('SELECT'):
                result = cur.fetchall()
                results.append([dict(row) for row in result])
                # Check if this looks like a user verification query
                if 'login=' in q.lower() and 'user' in q.lower():
                    if result:
                        user_data = dict(result[0])
                        # Remove sensitive fields
                        user_data.pop('password', None)
                        user_data.pop('password_renew_hash', None)
                        created_user = user_data
            else:
                results.append({'affected_rows': cur.rowcount})
        
        # If we didn't capture user data from queries, try to get it from form data
        if not created_user and 'login' in data:
            cur.execute(
                'SELECT id, login, name, email, enabled, account_expired, account_locked, password_expired, preferred_language, created_at FROM "user" WHERE login = %s',
                (data['login'],)
            )
            result = cur.fetchone()
            if result:
                created_user = dict(result)
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Get database config for audit information
        db_cfg = _resolve_db_cfg(app_key, env_key)
        database_name = db_cfg.get('database', 'unknown') if db_cfg else 'unknown'

        response_data = {
            'status': 'success',
            'app': (app_key or DEFAULT_APP),
            'env': (env_key or 'DEFAULT'),
            'database': database_name,
            'host': db_cfg.get('host', 'unknown') if db_cfg else 'unknown',
            'port': db_cfg.get('port', 5432) if db_cfg else 5432,
            'results': results
        }
        
        if created_user:
            response_data['user'] = created_user
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Query error: {e}'
        }), 500

@app.route('/api/db/user_exists', methods=['POST'])
@login_required
def user_exists():
    """Check if a user exists in the selected database by login and/or email separately."""
    data = request.json or {}
    app_key = data.get('app')
    env_key = data.get('env')
    login = data.get('login')
    email = data.get('email')

    if not login and not email:
        return jsonify({'status': 'error', 'message': 'Provide login or email'}), 400

    # First, test database connectivity
    try:
        conn = get_db_connection(app_key, env_key)
        # Test the connection with a simple query
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
    except Exception as e:
        app_name = app_key or DEFAULT_APP
        env_name = env_key or 'DEFAULT'
        return jsonify({
            'status': 'error',
            'message': f'Database not available: Cannot connect to {app_name} {env_name} database. Please ensure the database service is running.',
            'error_type': 'connection_error'
        }), 503

    try:
        # Re-establish connection for the actual queries
        conn = get_db_connection(app_key, env_key)
        cur = conn.cursor()

        results = {
            'status': 'success',
            'app': (app_key or DEFAULT_APP),
            'env': (env_key or 'DEFAULT'),
            'login_check': {'exists': False},
            'email_check': {'exists': False}
        }

        # Check login separately
        if login:
            cur.execute('SELECT id, login, name, email, enabled FROM "user" WHERE login = %s LIMIT 1', (login,))
            login_row = cur.fetchone()
            if login_row:
                results['login_check'] = {
                    'exists': True,
                    'user': dict(login_row)
                }

        # Check email separately
        if email:
            cur.execute('SELECT id, login, name, email, enabled FROM "user" WHERE LOWER(email) = LOWER(%s) LIMIT 1', (email,))
            email_row = cur.fetchone()
            if email_row:
                results['email_check'] = {
                    'exists': True,
                    'user': dict(email_row)
                }

        cur.close()
        conn.close()

        return jsonify(results)

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lookup error: {e}'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.logger.info(f"Starting enhanced server on http://0.0.0.0:{port}")
    app.logger.info("Features:")
    app.logger.info("  - Password hashing at /hash")
    app.logger.info("  - AI text extraction at /api/extract")
    app.logger.info("  - Database testing at /api/db/test")
    app.logger.info("Press Ctrl+C to stop")
    app.run(debug=True, host='0.0.0.0', port=port)
