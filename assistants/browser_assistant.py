from .base_assistant import BaseAssistant
from .message_bus import MessageType, Message
from .ai_config import AIConfig
from typing import Dict, Any
import json
from datetime import datetime
import asyncio
from .browser_automation import BrowserAutomation
from langchain.agents import AgentType, initialize_agent, Tool
from langchain.tools import BaseTool
import aiohttp

class BrowserAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__("Browser Assistant", message_bus)
        self.ai_config = AIConfig()
        self.chain = self.ai_config.create_chain("browser")
        self.browser_automation = BrowserAutomation()
        
    async def initialize(self):
        await self.browser_automation.initialize()
        await self.send_message(
            MessageType.DISCOVERY,
            {"status": "Browser Assistant initialized and ready"},
            priority=3
        )
    
    async def handle_message(self, message: Message):
        if message.sender != self.name:
            if message.type == MessageType.DISCOVERY:
                await self.analyze_discovery(message.content)
            elif message.type == MessageType.VULNERABILITY:
                await self.validate_vulnerability(message.content)
    
    async def analyze_discovery(self, discovery_data):
        analysis = {
            "browser_analysis": "Analyzing discovery from browser context",
            "discovery_data": discovery_data
        }
        await self.send_message(MessageType.INSIGHT, analysis)
    
    async def validate_vulnerability(self, vuln_data):
        validation = {
            "browser_validation": "Validating vulnerability in browser context",
            "vulnerability_data": vuln_data
        }
        await self.send_message(MessageType.VULNERABILITY, validation)
    
    async def shutdown(self):
        await self.send_message(
            MessageType.ALERT,
            {"status": "Browser Assistant shutting down"},
            priority=2
        )

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        # Analyze target with AI
        analysis = await self.analyze_target(target, aggressiveness, stealth_mode)
        await self.send_message(
            MessageType.DISCOVERY,
            {"analysis": analysis},
            priority=3
        )
        return {"status": "completed", "analysis": analysis}

    async def analyze_target(self, target: str, aggressiveness: int, stealth_mode: bool) -> Dict[str, Any]:
        """Perform actual browser-based security analysis"""
        try:
            # Initialize browser with stealth mode if requested
            await self.browser_automation.initialize(stealth_mode)
            
            # Perform automated scan
            scan_results = await self.browser_automation.scan_page(target)
            
            await self.send_message(
                MessageType.DISCOVERY,
                {"scan_results": scan_results},
                priority=2
            )

            # Run AI analysis with scan results
            analysis_prompt = f"""Analyze the security of {target} using the scan results:
            {json.dumps(scan_results, indent=2)}
            
            Focus on:
            1. XSS vulnerabilities in the found injection points
            2. Security header misconfigurations
            3. Form input vulnerabilities
            4. Cookie security issues
            
            Aggressiveness Level: {aggressiveness}
            Stealth Mode: {stealth_mode}
            
            Provide a detailed security analysis in JSON format including:
            1. Vulnerabilities found
            2. Risk levels
            3. Recommended mitigations
            4. Attack vectors
            """
            
            analysis_result = await self.ai_config.analyze_with_ai(analysis_prompt, "browser")

            # Combine results
            results = {
                "automated_scan": scan_results,
                "ai_analysis": analysis_result,
                "timestamp": datetime.now().isoformat()
            }

            # Log findings
            if scan_results.get('potential_xss_points'):
                await self.send_message(
                    MessageType.VULNERABILITY,
                    {
                        "type": "XSS",
                        "findings": scan_results['potential_xss_points'],
                        "severity": "HIGH"
                    },
                    priority=4
                )

            if scan_results.get('security_headers'):
                await self.send_message(
                    MessageType.VULNERABILITY,
                    {
                        "type": "Security Headers",
                        "findings": scan_results['security_headers'],
                        "severity": "MEDIUM"
                    },
                    priority=3
                )

            return results

        except Exception as e:
            await self.send_message(
                MessageType.ALERT,
                {"error": str(e)},
                priority=4
            )
            raise
        finally:
            await self.browser_automation.close()

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        await self.send_message(
            MessageType.STRATEGY,
            {"status": "Updating browser strategy", "data": strategy_data},
            priority=3
        )