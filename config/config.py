import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MODEL_NAME = os.getenv('MODEL_NAME', 'gpt-4o-2024-08-06')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    LANGSMITH_API_KEY = os.getenv('LANGSMITH_API_KEY')
    
    BROWSER_SETTINGS = {
        'headless': True,
        'browser_type': 'chromium'  # Options: 'chromium', 'firefox', 'webkit'
    }
    
    TERMINAL_SETTINGS = {
        'shell': '/bin/bash'
    }
    
    LANGCHAIN_SETTINGS = {
        'api_key': os.getenv('LANGCHAIN_API_KEY'),
        'serpapi_api_key': os.getenv('SERPAPI_API_KEY')
    } 
    
    # LangSmith settings
    os.environ["LANGSMITH_TRACING_V2"] = "true"
    os.environ["LANGSMITH_API_KEY"] = LANGSMITH_API_KEY
    os.environ["LANGSMITH_PROJECT"] = "team-assistants"
    
    AGENT_INSTRUCTIONS = {
        "browser": {
            "allowed_domains": ["example.com", "github.com"],
            "max_depth": 3,
            "timeout": 30,
            "instructions": """
            Browser Assistant Guidelines:
            - Only visit allowed domains
            - Respect robots.txt
            - Maximum page depth: 3
            - Timeout after 30 seconds
            """
        },
        "terminal": {
            "allowed_commands": ["ls", "pwd", "echo", "date"],
            "blocked_commands": ["rm", "sudo", "chmod"],
            "instructions": """
            Terminal Assistant Guidelines:
            - Only execute allowed commands
            - Never use sudo
            - Verify command safety
            """
        }
    }
    
    SECURITY_SETTINGS = {
        'output_dir': 'security_scans',
        'wpscan_api_key': os.getenv('WPSCAN_API_KEY'),
        'allowed_domains': ['example.com'],  # Add authorized domains
        'max_scan_duration': 3600,  # Maximum scan duration in seconds
        'instructions': """
        Security Scanning Tools Available:
        
        1. SQLMap:
        - SQL injection vulnerability scanner
        - Use for testing database security
        - Follows ethical hacking guidelines
        
        2. WPScan:
        - WordPress security scanner
        - Identifies vulnerable plugins/themes
        - Requires valid API key
        
        3. Arachni:
        - Web application security scanner
        - Comprehensive vulnerability assessment
        - Resource-intensive, use judiciously
        
        Usage Guidelines:
        - Only scan authorized domains
        - Respect rate limits and scan durations
        - Handle findings confidentially
        - Document all scan results
        """
    }