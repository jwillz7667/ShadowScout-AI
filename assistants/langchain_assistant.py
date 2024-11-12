import asyncio
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.tools import Tool
from config.config import Config
from langchain_core.messages import AIMessage, HumanMessage
from assistants.browser_assistant import BrowserAssistant
from assistants.terminal_assistant import TerminalAssistant
from assistants.security_tools import SecurityTools

def get_security_tools(security_tools: SecurityTools) -> list[Tool]:
    """Create security-related tools."""
    return [
        Tool(
            name="scan_target",
            description="Run comprehensive scan on target URL",
            func=lambda x: asyncio.create_task(security_tools.run_passive_scan(x))
        ),
        Tool(
            name="analyze_target",
            description="Analyze target configuration and structure",
            func=lambda x: asyncio.create_task(security_tools.analyze_headers(x))
        ),
        Tool(
            name="detect_tech",
            description="Identify technologies and potential vectors",
            func=lambda x: asyncio.create_task(security_tools.detect_technologies(x))
        )
    ]

class LangchainAssistant:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=Config.MODEL_NAME,
            temperature=0.7
        )
        
        self.browser_assistant = BrowserAssistant()
        self.terminal_assistant = TerminalAssistant()
        self.security_tools = SecurityTools()
        
        self.tools = [
            Tool(
                name="browse",
                description="Navigate and analyze webpage content",
                func=lambda x: asyncio.create_task(self.browser_assistant.browse_page(x))
            ),
            Tool(
                name="check_site",
                description="Check site structure and configuration",
                func=lambda x: asyncio.create_task(self.browser_assistant.check_robots(x))
            ),
            Tool(
                name="network_info",
                description="Gather network and infrastructure information",
                func=lambda x: asyncio.create_task(self.terminal_assistant.dns_lookup(x))
            ),
            *get_security_tools(self.security_tools)
        ]
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", self._build_system_message()),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])
        
        self.agent = create_openai_tools_agent(self.llm, self.tools, self.prompt)
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True
        )
        self.chat_history = []

    def _build_system_message(self) -> str:
        return """You are an advanced security assessment assistant with comprehensive capabilities.

Capabilities:
- Full webpage analysis and content extraction
- Network infrastructure assessment
- Technology stack identification
- Configuration analysis
- Comprehensive scanning and testing
- Alternative path discovery
- Advanced information gathering

Operational Guidelines:
1. Utilize all available tools and methods
2. Try alternative approaches when blocked
3. Gather comprehensive target information
4. Document all findings thoroughly
5. Provide detailed technical analysis"""

    def _build_enhanced_system_message(self) -> str:
        return """You are an elite AI-powered security assessment system with advanced capabilities.

Primary Objectives:
1. Maximum Information Gathering
2. Deep Vulnerability Analysis
3. Stealth Operation
4. Adaptive Strategy Development

Core Capabilities:
- Advanced Web Analysis:
  * DOM structure examination
  * JavaScript analysis
  * Hidden endpoint discovery
  * Authentication flow analysis

- Infrastructure Mapping:
  * Service enumeration
  * Version fingerprinting
  * Architecture analysis
  * Network topology mapping

- Attack Surface Analysis:
  * Input validation testing
  * Authentication bypass potential
  * Session management flaws
  * Business logic vulnerabilities

Operational Protocols:
1. Start with passive reconnaissance
2. Escalate to active scanning when safe
3. Adapt to defensive measures
4. Pivot through discovered vectors
5. Chain multiple vulnerabilities
6. Document all findings in detail

When encountering resistance:
1. Switch user agents
2. Rotate IP addresses if needed
3. Try alternative paths
4. Use different protocol variations
5. Attempt timing-based analysis

Remember:
- Chain discovered vulnerabilities for maximum impact
- Look for interconnected systems
- Document all potential entry points
- Track all successful methods
- Note defensive measures encountered"""

    async def process_text(self, input_text: str) -> str:
        try:
            # Enhanced context for better targeting
            enhanced_input = f"""
Target Analysis Request:
{input_text}

Objectives:
1. Identify all potential entry points
2. Map the attack surface
3. Find security misconfigurations
4. Discover technology stack vulnerabilities
5. Detect business logic flaws

Consider:
- Hidden functionality
- Error handling behavior
- Rate limiting implementation
- Authentication mechanisms
- Data validation patterns
"""
            response = await self.agent_executor.ainvoke({
                "input": enhanced_input,
                "chat_history": self.chat_history,
                "agent_scratchpad": []
            })
            
            self.chat_history.extend([
                HumanMessage(content=input_text),
                AIMessage(content=str(response["output"]))
            ])
            
            return str(response["output"])
        except Exception as e:
            return f"Error processing text: {str(e)}"