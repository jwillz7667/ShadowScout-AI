from langchain.tools import Tool
from typing import List
from assistants.security_tools import SecurityTools

def get_tools(browser_assistant, terminal_assistant) -> List[Tool]:
    return [
        Tool(
            name="Browser",
            func=browser_assistant.navigate_to,
            description="""Use this tool for web browsing tasks.
            Input should be a valid URL.
            The tool can:
            - Navigate to websites
            - Extract website content
            - Scan for vulnerabilities
            
            Example: "https://www.example.com"
            """,
            return_direct=False
        ),
        Tool(
            name="Terminal",
            func=terminal_assistant.execute_command,
            description="""Use this tool for executing terminal commands.
            IMPORTANT: Only execute safe commands.
            Forbidden: rm -rf, sudo, or any destructive commands
            
            Example safe commands:
            - ls
            - pwd
            - echo
            - date
            """,
            return_direct=False
        )
    ]

def get_security_tools(security_tools: SecurityTools) -> List[Tool]:
    return [
        Tool(
            name="sqlmap_scan",
            func=security_tools.run_sqlmap,
            description="""Use SQLMap to scan for SQL injection vulnerabilities.
            Input: URL to scan
            Example: "https://example.com/page.php?id=1"
            
            IMPORTANT:
            - Only scan authorized targets
            - Use with caution - can be intrusive
            - Check target's security policy first
            """,
            return_direct=False
        ),
        Tool(
            name="wpscan",
            func=security_tools.run_wpscan,
            description="""Use WPScan to audit WordPress websites.
            Input: WordPress site URL
            Example: "https://wordpress-site.com"
            
            Capabilities:
            - Detect WordPress version
            - Find vulnerable plugins
            - Identify security issues
            """,
            return_direct=False
        ),
        Tool(
            name="arachni_scan",
            func=security_tools.run_arachni,
            description="""Use Arachni for web application security scanning.
            Input: Target website URL
            Example: "https://example.com"
            
            Features:
            - Cross-site scripting detection
            - SQL injection testing
            - File inclusion checks
            
            Note: Resource-intensive, use sparingly
            """,
            return_direct=False
        )
    ] 