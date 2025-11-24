"""
Configuration and Environment Variables
Manages API keys, models, and application settings
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration from environment variables"""
    
    # ========== AI Provider Configuration ==========
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')
    
    # Choose AI provider: 'claude' or 'gemini'
    # AI_PROVIDER = os.getenv('AI_PROVIDER', 'claude').lower()
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'gemini').lower()
    
    # Model selection
    CLAUDE_MODEL = os.getenv('CLAUDE_MODEL', 'claude-3-5-sonnet-20241022')
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3-pro-preview')
    
    # ========== Flask Configuration ==========
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # ========== Logging Configuration ==========
    LOG_DIR = Path('logs')
    LOG_FILE = LOG_DIR / 'agent_interactions.log'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # ========== Security Configuration ==========
    MAX_TOKENS = int(os.getenv('MAX_TOKENS', 1024))
    TOKEN_EXPIRY_SECONDS = int(os.getenv('TOKEN_EXPIRY_SECONDS', 3600))
    OBO_TOKEN_EXPIRY_SECONDS = int(os.getenv('OBO_TOKEN_EXPIRY_SECONDS', 600))
    
    @classmethod
    def validate(cls):
        """
        Validate configuration and return list of errors
        
        Returns:
            list: Error messages if validation fails, empty list otherwise
        """
        errors = []
        
        if cls.AI_PROVIDER == 'claude' and not cls.ANTHROPIC_API_KEY:
            errors.append(" ANTHROPIC_API_KEY not set but AI_PROVIDER is 'claude'")
        
        if cls.AI_PROVIDER == 'gemini' and not cls.GOOGLE_API_KEY:
            errors.append(" GOOGLE_API_KEY not set but AI_PROVIDER is 'gemini'")
        
        if cls.AI_PROVIDER not in ['claude', 'gemini']:
            errors.append(f" Invalid AI_PROVIDER: {cls.AI_PROVIDER}. Must be 'claude' or 'gemini'")
        
        # Create log directory if it doesn't exist
        cls.LOG_DIR.mkdir(exist_ok=True)
        
        return errors
    
    @classmethod
    def get_active_model(cls):
        """Get the active AI model name"""
        if cls.AI_PROVIDER == 'claude':
            return cls.CLAUDE_MODEL
        else:
            return cls.GEMINI_MODEL
    
    @classmethod
    def print_config(cls):
        """Print current configuration for debugging"""
        print("="*80)
        print("SECURE AI AGENT - CONFIGURATION")
        print("="*80)
        print(f"AI Provider: {cls.AI_PROVIDER.upper()}")
        print(f"Model: {cls.get_active_model()}")
        print(f"API Key Set: {'Key Valid' if (cls.AI_PROVIDER == 'claude' and cls.ANTHROPIC_API_KEY) or (cls.AI_PROVIDER == 'gemini' and cls.GOOGLE_API_KEY) else '❌'}")
        print(f"Flask Debug: {cls.DEBUG}")
        print(f"Server: {cls.HOST}:{cls.PORT}")
        print(f"Log File: {cls.LOG_FILE}")
        print("="*80)
