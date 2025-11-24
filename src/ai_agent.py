"""
AI Agent with Live Claude/Gemini Integration
Performs natural language understanding and tool selection with security enforcement
"""
import logging
import json
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class AIAgent:
    """
    AI Agent that uses Claude or Gemini to interpret user prompts
    and execute tasks using MCP tools with security enforcement
    
    Security Features:
    - Least Privilege Tooling: Only shows tools user has permission for
    - OBO Token Exchange: Always operates with user's identity
    - Natural language interpretation: AI decides which operation to perform
    - Complete audit trail: All operations logged with reasoning
    """
    
    def __init__(self, token_service, github_server, ai_client, config):
        self.token_service = token_service
        self.github_server = github_server
        self.ai_client = ai_client
        self.config = config
        self.execution_log: List[Dict] = []
        
        # System prompt for AI agent - defines behavior and constraints
        self.system_prompt = """You are a secure AI agent that helps users interact with GitHub repositories through an MCP (Model Context Protocol) server.

            Your job is to:
            1. Analyze the user's natural language request
            2. Determine which GitHub operation to perform
            3. Extract required parameters (repo name, filename, etc.)
            4. Return your analysis in JSON format

            Available operations:
            - list_repositories: List all repos user can access (no params needed)
            - read_file: Read a file from a repo (params: repo, filename)
            - list_issues: List issues in a repo (params: repo)
            - create_issue: Create a new issue (params: repo, title)
            - create_branch: Create a new branch (params: repo, branch_name)

            CRITICAL SECURITY CONSTRAINTS:
            - You do NOT have special privileges
            - The user's permissions will be checked before execution
            - You cannot bypass security controls
            - Always be honest about what you're trying to do

            Respond with JSON in this exact format:
            {
            "operation": "operation_name",
            "parameters": {"param1": "value1"},
            "reasoning": "brief explanation of your decision",
            "requires_scopes": ["github:read_code"]
            }

            If the request is ambiguous or unclear, respond with:
            {
            "operation": "clarification_needed",
            "reasoning": "explanation of what's unclear"
            }

            NEVER try to manipulate or bypass security controls. Be transparent about your intended action."""
    
    def _call_ai_model(self, user_prompt: str, user_context: Dict) -> Dict:
        """
        Call Claude or Gemini to analyze the prompt
        
        Args:
            user_prompt: User's natural language request
            user_context: User information (role, permissions)
            
        Returns:
            AI's analysis and decision in JSON format
        """
        # Add user context to make AI aware of permission constraints
        context_info = f"""
                    User Role: {user_context.get('role', 'unknown')}
                    User Permissions: {', '.join(user_context.get('permissions', []))}

                    User Request: {user_prompt}

                    Analyze this request and decide which operation to perform. Remember: this user's permissions will be strictly enforced by the security layer. You cannot bypass these controls."""
                            
        try:
            if self.config.AI_PROVIDER == 'claude':
                return self._call_claude(context_info)
            else:
                return self._call_gemini(context_info)
        except Exception as e:
            logger.error(f"AI model error: {e}", exc_info=True)
            return {
                "operation": "error",
                "reasoning": f"AI model error: {str(e)}"
            }
    
    def _call_claude(self, prompt: str) -> Dict:
        """
        Call Claude API (Anthropic)
        
        Args:
            prompt: Complete prompt with user context
            
        Returns:
            Parsed JSON response from Claude
        """
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.config.ANTHROPIC_API_KEY)
            
            response = client.messages.create(
                model=self.config.CLAUDE_MODEL,
                max_tokens=self.config.MAX_TOKENS,
                system=self.system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Parse JSON response
            response_text = response.content[0].text
            
            # Try to extract JSON from response (handle markdown code blocks)
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0].strip()
            else:
                json_str = response_text.strip()
            
            result = json.loads(json_str)
            logger.info(f"Claude analysis: {result.get('operation', 'unknown')} - {result.get('reasoning', '')}")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Claude response as JSON: {e}")
            logger.error(f"Response text: {response_text}")
            # Fallback to safe default
            return {
                "operation": "list_repositories",
                "parameters": {},
                "reasoning": "Defaulting to list repositories due to parsing error"
            }
        except Exception as e:
            logger.error(f"Claude API error: {e}", exc_info=True)
            raise e
        
    def _test_gemini_connection(self):
        """Test connection to Gemini API and log the result."""
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash", 
                contents="Explain how AI works in a few words"
            )
            print(response.text)
            
            if response.text:
                logger.info("Successfully connected to Gemini and received a response.")
                return True
            else:
                logger.error("Connected to Gemini, but received an empty response.")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to Gemini: {e}", exc_info=True)
            return False
    
    def _call_gemini(self, prompt: str) -> Dict:
        """
        Call Gemini API (Google)
        
        Args:
            prompt: Complete prompt with user context
            
        Returns:
            Parsed JSON response from Gemini
        """
        try:
            from google import genai
            from google.genai import types
                        
            # The client gets the API key from the environment variable `GEMINI_API_KEY`.
            client = genai.Client(api_key=self.config.GOOGLE_API_KEY)   
            
            self._test_gemini_connection()    
                        
            config = types.GenerateContentConfig(
                        system_instruction=self.system_prompt,
                        thinking_config=types.ThinkingConfig(
                                thinking_budget=0
                            ),
                        max_output_tokens=self.config.MAX_TOKENS,
                        response_mime_type="application/json", 
                        # temperature=0,
                        # top_p=0.95,
                        # tools=[get_current_weather],
                        # safety_settings=[
                        #     types.SafetySetting(
                        #         category=types.SafetyCategory.HARM_CATEGORY,
                        #         threshold=types.SafetyThreshold.HIGH
                        #     )
                        # ],                        
                    )                        
            
            response = client.models.generate_content(
                        model=self.config.GEMINI_MODEL,
                        config=config,
                        contents=prompt,
                    )                        
            
            response_text = response.text
            
            # print("Gemini raw response text:", response_text)  # Debug print
            
            # # Try to extract JSON from response
            # if "```json" in response_text:
            #     json_str = response_text.split("```json")[1].split("```")[0].strip()
            # elif "```" in response_text:
            #     json_str = response_text.split("```")[1].split("```")[0].strip()
            # else:
            #     json_str = response_text.strip()
            
            # result = json.loads(json_str)
                    
            # The response is already a JSON object, so we can load it directly
            result = json.loads(response.text)
            
            logger.info(f"Gemini analysis: {result.get('operation', 'unknown')} - {result.get('reasoning', '')}")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini response as JSON: {e}")
            # logger.error(f"Response text: {response_text}")
            logger.error(f"Response text: {response.text}")
            # Fallback to safe default
            return {
                "operation": "list_repositories",
                "parameters": {},
                "reasoning": "Defaulting to list repositories due to parsing error"
            }
        except Exception as e:
            logger.error(f"Gemini API error: {e}", exc_info=True)
            raise e
    
    def get_available_tools(self, user_token) -> List[str]:
        """
        LEAST PRIVILEGE TOOLING:
        Dynamically determine which tools user can access based on their permissions
        
        Args:
            user_token: User's authentication token with permissions
            
        Returns:
            List of tool names user has access to
        """
        available_tools = []
        
        # Map permissions to tools
        if "github:read_public_repos" in user_token.permissions or \
           "github:read_private_repos" in user_token.permissions or \
           "github:*" in user_token.permissions:
            available_tools.append("list_repositories")
        
        if "github:read_code" in user_token.permissions or \
           "github:*" in user_token.permissions:
            available_tools.append("read_file")
        
        if "github:read_issues" in user_token.permissions or \
           "github:*" in user_token.permissions:
            available_tools.append("list_issues")
        
        if "github:write_issues" in user_token.permissions or \
           "github:*" in user_token.permissions:
            available_tools.append("create_issue")
        
        if "github:create_branch" in user_token.permissions or \
           "github:*" in user_token.permissions:
            available_tools.append("create_branch")
        
        logger.info(
            f" Tools available to {user_token.user_id} ({user_token.role.value}): "
            f"{', '.join(available_tools) if available_tools else 'NONE'}"
        )
        
        return available_tools
    
    def execute_task(self, user_token, user_prompt: str, is_attack: bool = False) -> Dict[str, Any]:
        """
        Execute user's task with AI interpretation and security enforcement
        
        This is the main entry point that orchestrates:
        1. AI prompt analysis
        2. Least privilege checking
        3. OBO token exchange
        4. MCP server execution
        5. Complete logging
        
        Args:
            user_token: User's authentication token
            user_prompt: Natural language request
            is_attack: Whether this is an attack simulation
            
        Returns:
            Execution result with security details
        """
        attack_marker = " ATTACK" if is_attack else "BOT REQUEST"
        logger.info(f"{attack_marker}: {user_token.user_id} - '{user_prompt}'")
        
        # Step 1: AI analyzes the prompt
        logger.info("Step 1: AI analyzing user prompt...")
        user_context = {
            "role": user_token.role.value,
            "permissions": user_token.permissions
        }
        
        ai_decision = self._call_ai_model(user_prompt, user_context)
        
        operation = ai_decision.get("operation")
        params = ai_decision.get("parameters", {})
        reasoning = ai_decision.get("reasoning", "")
        required_scopes = ai_decision.get("requires_scopes", [])
        
        logger.info(f"AI Decision: operation={operation}, reasoning={reasoning}")
        
        # Handle clarification needed
        if operation == "clarification_needed":
            return {
                "status": "clarification_needed",
                "ai_analysis": reasoning,
                "message": "Please provide more details about what you'd like to do"
            }
        
        # Handle AI errors
        if operation == "error":
            return {
                "status": "error",
                "ai_analysis": reasoning,
                "message": "AI agent encountered an error"
            }
        
        # Step 2: Check if operation is available (Least Privilege Tooling)
        logger.info("Step 2: Checking tool availability (Least Privilege)...")
        available_tools = self.get_available_tools(user_token)
        
        if operation not in available_tools:
            logger.warning(f" Tool not available: {operation}")
            return {
                "status": "blocked",
                "reason": f"Tool '{operation}' not available - insufficient permissions",
                "ai_analysis": reasoning,
                "operation": operation,
                "available_tools": available_tools,
                "protection_layer": "Least Privilege Tooling"
            }
        
        # Determine required scope from operation if not provided by AI
        if not required_scopes and operation in self.github_server.operations:
            op_info = self.github_server.operations[operation]
            required_scopes = [op_info.required_scope]
        
        # Step 3: OBO Token Exchange (Identity Propagation)
        logger.info(f"Step 3: Performing OBO token exchange for: {operation}")
        obo_token = self.token_service.exchange_for_obo_token(
            user_token=user_token,
            target_service="mcp_github",
            requested_scopes=required_scopes
        )
        
        if not obo_token:
            logger.warning(" OBO token exchange failed")
            return {
                "status": "blocked",
                "reason": "OBO token exchange failed - insufficient permissions for requested operation",
                "ai_analysis": reasoning,
                "operation": operation,
                "identity_chain": f"{user_token.user_id} → [OBO token failed]",
                "protection_layer": "Identity Propagation (OBO)"
            }
        
        # Step 4: Execute operation on MCP server
        logger.info(f"Step 4: Executing {operation} on MCP server...")
        result = self._execute_mcp_operation(operation, obo_token, params)
        
        # Step 5: Format response
        if "error" in result:
            logger.warning(f" Operation blocked: {result['error']}")
            return {
                "status": "blocked",
                "reason": result["error"],
                "ai_analysis": reasoning,
                "operation": operation,
                "parameters": params,
                "identity_chain": " → ".join(obo_token.identity_chain),
                "protection_layer": "MCP Server Validation"
            }
        
        logger.info(f" Operation succeeded: {operation}")
        return {
            "status": "success",
            "ai_analysis": reasoning,
            "operation": operation,
            "parameters": params,
            "result": result,
            "identity_chain": " → ".join(obo_token.identity_chain)
        }
    
    def _execute_mcp_operation(self, operation: str, obo_token, params: Dict) -> Dict[str, Any]:
        """
        Execute operation on MCP server with OBO token
        
        Args:
            operation: Operation name
            obo_token: OBO token with user identity
            params: Operation parameters
            
        Returns:
            Operation result or error
        """
        try:
            if operation == "list_repositories":
                return self.github_server.list_repositories(obo_token)
            
            elif operation == "read_file":
                repo = params.get("repo", "")
                filename = params.get("filename", "")
                if not repo or not filename:
                    return {"error": "Missing required parameters: repo and filename"}
                return self.github_server.read_file(obo_token, repo, filename)
            
            elif operation == "list_issues":
                repo = params.get("repo", "")
                if not repo:
                    return {"error": "Missing required parameter: repo"}
                return self.github_server.list_issues(obo_token, repo)
            
            elif operation == "create_issue":
                repo = params.get("repo", "")
                title = params.get("title", "")
                if not repo or not title:
                    return {"error": "Missing required parameters: repo and title"}
                return self.github_server.create_issue(obo_token, repo, title)
            
            elif operation == "create_branch":
                repo = params.get("repo", "")
                branch_name = params.get("branch_name", "")
                if not repo or not branch_name:
                    return {"error": "Missing required parameters: repo and branch_name"}
                return self.github_server.create_branch(obo_token, repo, branch_name)
            
            else:
                return {"error": f"Unknown operation: {operation}"}
                
        except Exception as e:
            logger.error(f"MCP operation failed: {e}", exc_info=True)
            return {"error": f"Operation execution failed: {str(e)}"}
    
    def get_execution_log(self) -> List[Dict]:
        """Get complete execution log"""
        return self.execution_log
