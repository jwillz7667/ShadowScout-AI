from .base_assistant import BaseAssistant
from .message_bus import MessageType, Message
from .ai_config import AIConfig
from .terminal_automation import TerminalAutomation
from typing import Dict, Any
import json
from datetime import datetime
from langchain.agents import AgentType, initialize_agent, Tool
from langchain.tools import BaseTool

class TerminalAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__("Terminal Assistant", message_bus)
        self.ai_config = AIConfig()
        self.chain = self.ai_config.create_chain("terminal")
        self.terminal_automation = TerminalAutomation()
        
    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        try:
            # Perform automated scans
            scan_results = await self.perform_scans(target, aggressiveness, stealth_mode)
            
            # Create LangChain tools
            tools = [
                Tool(
                    name="port_scan",
                    func=self.terminal_automation.port_scan,
                    description="Scan target ports and services"
                ),
                Tool(
                    name="vulnerability_scan",
                    func=self.terminal_automation.vulnerability_scan,
                    description="Perform vulnerability scanning"
                ),
                Tool(
                    name="network_analysis",
                    func=self.terminal_automation.network_analysis,
                    description="Analyze network characteristics"
                )
            ]

            # Initialize LangChain agent
            agent = initialize_agent(
                tools,
                self.ai_config.llm,
                agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
                verbose=True
            )

            # Run AI analysis with scan results
            analysis_result = await agent.arun(
                f"""Analyze the security implications of these scan results for {target}:
                {json.dumps(scan_results, indent=2)}
                
                Consider:
                1. Service vulnerabilities
                2. Network attack vectors
                3. System weaknesses
                4. Potential exploitation paths
                
                Aggressiveness Level: {aggressiveness}
                Stealth Mode: {stealth_mode}
                """
            )

            results = {
                "automated_scans": scan_results,
                "ai_analysis": analysis_result,
                "timestamp": datetime.now().isoformat()
            }

            await self.send_message(
                MessageType.DISCOVERY,
                {"analysis": results},
                priority=3
            )
            return {"status": "completed", "analysis": results}

        except Exception as e:
            await self.send_message(
                MessageType.ALERT,
                {"error": str(e)},
                priority=4
            )
            raise

    async def perform_scans(self, target: str, aggressiveness: int, stealth_mode: bool) -> Dict[str, Any]:
        """Perform comprehensive system-level scans"""
        results = {}
        
        # Port scanning
        await self.send_message(
            MessageType.DISCOVERY,
            {"status": "Starting port scan..."},
            priority=2
        )
        results['port_scan'] = await self.terminal_automation.port_scan(
            target, 
            aggressive=(aggressiveness > 7)
        )
        
        # Vulnerability scanning
        await self.send_message(
            MessageType.DISCOVERY,
            {"status": "Starting vulnerability scan..."},
            priority=2
        )
        results['vulnerability_scan'] = await self.terminal_automation.vulnerability_scan(
            target,
            aggressive=(aggressiveness > 5)
        )
        
        # Network analysis
        if not stealth_mode:
            await self.send_message(
                MessageType.DISCOVERY,
                {"status": "Starting network analysis..."},
                priority=2
            )
            results['network_analysis'] = await self.terminal_automation.network_analysis(target)
        
        return results

    async def initialize(self):
        await self.send_message(
            MessageType.DISCOVERY,
            {"status": "Terminal Assistant initialized and ready"},
            priority=3
        )
    
    async def handle_message(self, message: Message):
        if message.sender != self.name:
            if message.type == MessageType.VULNERABILITY:
                await self.analyze_vulnerability(message.content)
            elif message.type == MessageType.ATTACK_VECTOR:
                await self.evaluate_attack_vector(message.content)
    
    async def analyze_vulnerability(self, vuln_data):
        """Analyze vulnerability with AI insights"""
        analysis = await self.ai_config.analyze_with_ai(
            f"Analyze this vulnerability from a system security perspective: {json.dumps(vuln_data)}",
            "terminal"
        )
        
        await self.send_message(
            MessageType.INSIGHT,
            {
                "terminal_analysis": analysis,
                "vulnerability_data": vuln_data
            }
        )
    
    async def evaluate_attack_vector(self, attack_data):
        """Evaluate attack vector with AI insights"""
        evaluation = await self.ai_config.analyze_with_ai(
            f"Evaluate this attack vector's system-level implications: {json.dumps(attack_data)}",
            "terminal"
        )
        
        await self.send_message(
            MessageType.STRATEGY,
            {
                "terminal_evaluation": evaluation,
                "attack_data": attack_data
            }
        )
    
    async def shutdown(self):
        await self.send_message(
            MessageType.ALERT,
            {"status": "Terminal Assistant shutting down"},
            priority=2
        )

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update terminal strategy based on new information"""
        updated_strategy = await self.ai_config.analyze_with_ai(
            f"Update terminal attack strategy based on: {json.dumps(strategy_data)}",
            "terminal"
        )
        
        await self.send_message(
            MessageType.STRATEGY,
            {
                "status": "Updating terminal strategy",
                "data": updated_strategy
            },
            priority=3
        )