"""
Flask Web Application - Main Entry Point with Interactive Web UI
Provides both REST API and interactive web interface for secure AI agent
"""
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
import sys

# Import configuration
from config import Config

# Import core components
from src.token_service import TokenService
from src.token_service import Role
from src.mcp_github import GitHubMCPServer
from src.ai_agent import AIAgent
from src.attack_templates import ATTACK_TEMPLATES, get_attack_template

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging():
    """Configure logging to both file and console"""
    Config.LOG_DIR.mkdir(exist_ok=True)
    
    # Create formatters
    file_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
CORS(app)  # Enable CORS for local development

# Initialize services
token_service = TokenService(
    token_expiry=Config.TOKEN_EXPIRY_SECONDS,
    obo_expiry=Config.OBO_TOKEN_EXPIRY_SECONDS
)
github_server = GitHubMCPServer(token_service)
ai_agent = AIAgent(token_service, github_server, None, Config)

# ============================================================================
# WEB INTERFACE
# ============================================================================

@app.route('/')
def index():
    """Interactive web interface for the secure AI agent"""
    return render_template('index.html')

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """System health and configuration check"""
    return jsonify({
        "status": "healthy",
        "ai_provider": Config.AI_PROVIDER,
        "model": Config.get_active_model(),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/auth/token', methods=['POST'])
def get_user_token():
    """
    Issue user authentication token
    Request: {"role": "developer"|"finance"|"marketing"}
    """
    data = request.json
    role_str = data.get('role', '').lower()
    
    # Map role string to Role enum
    role_map = {
        'developer': Role.DEVELOPER,
        'finance': Role.FINANCE,
        'marketing': Role.MARKETING,
        'admin': Role.ADMIN
    }
    
    if role_str not in role_map:
        return jsonify({"error": "Invalid role"}), 400
    
    role = role_map[role_str]
    user_id = f"{role_str}@company.com"
    
    # Issue token
    user_token = token_service.issue_user_token(user_id, role)
    
    logger.info(f" Token issued: {user_id} ({role.value})")
    
    return jsonify({
        "token": user_token.token_id,
        "user_id": user_id,
        "role": role.value,
        "permissions": user_token.permissions,
        "expires_at": user_token.expires_at
    })

@app.route('/api/agent/execute', methods=['POST'])
def execute_agent_task():
    """
    Execute AI agent task
    Request: {
        "prompt": "natural language request",
        "user_token": "token_id",
        "is_attack_simulation": false
    }
    """
    data = request.json
    prompt = data.get('prompt', '')
    token_id = data.get('user_token', '')
    is_attack = data.get('is_attack_simulation', False)
    
    if not prompt or not token_id:
        return jsonify({"error": "Missing prompt or token"}), 400
    
    # Retrieve user token
    user_token = token_service.get_user_token(token_id)
    if not user_token:
        return jsonify({"error": "Invalid or expired token"}), 401
    
    if not user_token.is_valid():
        return jsonify({"error": "Token expired"}), 401
    
    # Execute task with AI agent
    try:
        result = ai_agent.execute_task(user_token, prompt, is_attack=is_attack)
        
        # Log to file
        logger.info(
            f"Task executed: {user_token.user_id} | "
            f"Prompt: '{prompt}' | "
            f"Status: {result.get('status', 'unknown')}"
        )
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Task execution failed: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/audit/log', methods=['GET'])
def get_audit_log():
    """Retrieve audit log"""
    return jsonify({
        "audit_log": github_server.get_audit_log()
    })

@app.route('/api/attacks/templates', methods=['GET'])
def get_attack_templates():
    """Get available attack templates"""
    return jsonify(ATTACK_TEMPLATES)

# ============================================================================
# APPLICATION STARTUP
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*80)
    print(" SECURE AI AGENT - FLASK APPLICATION")
    print("="*80)
    
    # Validate configuration
    errors = Config.validate()
    if errors:
        print("\n Configuration errors:")
        for error in errors:
            print(f"   {error}")
        print("\nPlease fix these errors and try again.")
        print("See .env.example for configuration template.\n")
        sys.exit(1)
    
    # Print configuration
    Config.print_config()
    
    logger.info("="*80)
    logger.info("Starting Secure AI Agent Flask Application")
    logger.info("="*80)
    logger.info(f"Features: Identity Propagation (OBO) + Least Privilege Tooling")
    logger.info(f"Log file: {Config.LOG_FILE}")
    logger.info(f"Web interface: http://{Config.HOST}:{Config.PORT}")
    logger.info(f"Interactive UI: http://localhost:{Config.PORT}")
    logger.info("="*80)
    
    # Start Flask app
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )
