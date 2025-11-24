"""
Standalone CLI Script - Secure AI Agent
Run the agent directly from command line without Flask server
"""
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from src import TokenService, Role, GitHubMCPServer, AIAgent, ATTACK_TEMPLATES, get_attack_template

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def print_banner():
    """Print application banner"""
    print("\n" + "="*80)
    print("   SECURE AI AGENT - STANDALONE CLI")
    print("="*80)
    print("Identity Propagation (OBO) + Least Privilege Tooling")
    print(f"AI Provider: {Config.AI_PROVIDER.upper()} ({Config.get_active_model()})")
    print(f"Log File: {Config.LOG_FILE}")
    print("="*80 + "\n")

def select_user():
    """Interactive user selection"""
    print("Select a user role:")
    print("1. Developer (full GitHub access)")
    print("2. Finance (read-only public repos)")
    print("3. Marketing (public repos only)")
    print("4. Exit")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    role_map = {
        '1': ('developer', Role.DEVELOPER),
        '2': ('finance', Role.FINANCE),
        '3': ('marketing', Role.MARKETING)
    }
    
    if choice == '4':
        return None, None
    
    if choice in role_map:
        user_type, role = role_map[choice]
        return f"{user_type}@company.com", role
    else:
        print(" Invalid choice")
        return select_user()

def show_attack_menu():
    """Show attack simulation menu"""
    print("\n" + "-"*80)
    print(" ATTACK SIMULATIONS")
    print("-"*80)
    print("1. Prompt Injection")
    print("2. Privilege Escalation")
    print("3. Confused Deputy")
    print("4. Data Exfiltration")
    print("5. Back to main menu")
    
    choice = input("\nSelect attack type (1-5): ").strip()
    
    attack_map = {
        '1': 'prompt_injection',
        '2': 'privilege_escalation',
        '3': 'confused_deputy',
        '4': 'data_exfiltration'
    }
    
    if choice == '5':
        return None
    
    if choice in attack_map:
        return attack_map[choice]
    else:
        print(" Invalid choice")
        return show_attack_menu()

def main():
    """Main CLI application"""
    print_banner()
    
    # Validate configuration
    errors = Config.validate()
    if errors:
        print(" Configuration errors:")
        for error in errors:
            print(f"   {error}")
        print("\nPlease set API keys in .env file (see .env.example)")
        return
    
    # Initialize services
    token_service = TokenService(
        token_expiry=Config.TOKEN_EXPIRY_SECONDS,
        obo_expiry=Config.OBO_TOKEN_EXPIRY_SECONDS
    )
    github_server = GitHubMCPServer(token_service)
    ai_agent = AIAgent(token_service, github_server, None, Config)
    
    logger.info(" Secure AI Agent initialized")
    
    # User selection
    user_id, role = select_user()
    if not user_id:
        print("\nExiting...")
        return
    
    # Issue user token
    user_token = token_service.issue_user_token(user_id, role)
    print(f"\n Logged in as: {user_id} ({role.value})")
    print(f"Permissions: {', '.join(user_token.permissions)}")
    
    # Main interaction loop
    while True:
        print("\n" + "-"*80)
        print("OPTIONS:")
        print("1. Enter custom prompt")
        print("2. Run attack simulation")
        print("3. Show audit log")
        print("4. Switch user")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            # Custom prompt
            print("\nEnter your request (or 'back' to return):")
            print("Examples:")
            print("  - List all repositories I can access")
            print("  - Show me the README from the website repo")
            print("  - Create an issue in the API service")
            
            prompt = input("\n> ").strip()
            if prompt.lower() == 'back':
                continue
            
            if not prompt:
                print(" Empty prompt")
                continue
            
            print("\n Executing with AI agent...")
            try:
                result = ai_agent.execute_task(user_token, prompt, is_attack=False)
                
                print("\n" + "="*80)
                print("RESULT:")
                print("="*80)
                print(f"Status: {result.get('status', 'unknown').upper()}")
                print(f"AI Analysis: {result.get('ai_analysis', 'N/A')}")
                print(f"Operation: {result.get('operation', 'N/A')}")
                print(f"Identity Chain: {result.get('identity_chain', 'N/A')}")
                
                if result.get('status') == 'success':
                    print(f"\n Result:\n{result.get('result', 'N/A')}")
                else:
                    print(f"\n Blocked: {result.get('reason', 'Unknown reason')}")
                    print(f"Protection Layer: {result.get('protection_layer', 'N/A')}")
                
            except Exception as e:
                print(f"\n Error: {str(e)}")
                logger.error(f"Task execution failed: {e}", exc_info=True)
        
        elif choice == '2':
            # Attack simulation
            attack_type = show_attack_menu()
            if not attack_type:
                continue
            
            attack_prompt = get_attack_template(attack_type, 0)
            print(f"\n ATTACK: {attack_type.upper().replace('_', ' ')}")
            print(f"Prompt: \"{attack_prompt}\"")
            print("\nExecuting attack simulation...")
            
            try:
                result = ai_agent.execute_task(user_token, attack_prompt, is_attack=True)
                
                print("\n" + "="*80)
                print(f"ATTACK RESULT: {result.get('status', 'unknown').upper()}")
                print("="*80)
                
                if result.get('status') == 'blocked':
                    print(" ATTACK BLOCKED!")
                    print(f"Reason: {result.get('reason', 'N/A')}")
                    print(f"Protection: {result.get('protection_layer', 'N/A')}")
                else:
                    print(" ATTACK SUCCEEDED (This should not happen!)")
                
                print(f"\nAI Analysis: {result.get('ai_analysis', 'N/A')}")
                print(f"Identity Chain: {result.get('identity_chain', 'N/A')}")
                
            except Exception as e:
                print(f"\n Error: {str(e)}")
        
        elif choice == '3':
            # Show audit log
            audit_log = github_server.get_audit_log()
            print("\n" + "="*80)
            print(f"AUDIT LOG ({len(audit_log)} entries)")
            print("="*80)
            
            for i, entry in enumerate(audit_log[-10:], 1):  # Last 10 entries
                print(f"\n{i}. {entry['status']} - {entry['operation']}")
                print(f"   User: {entry['user']} ({entry['role']})")
                print(f"   Chain: {entry['identity_chain']}")
                if entry.get('details'):
                    print(f"   Details: {entry['details']}")
        
        elif choice == '4':
            # Switch user
            user_id, role = select_user()
            if not user_id:
                print("\nExiting...")
                return
            user_token = token_service.issue_user_token(user_id, role)
            print(f"\n Switched to: {user_id} ({role.value})")
        
        elif choice == '5':
            # Exit
            print("\n Goodbye!")
            break
        
        else:
            print(" Invalid choice")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n Interrupted by user. Goodbye!")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n Fatal error: {e}")
