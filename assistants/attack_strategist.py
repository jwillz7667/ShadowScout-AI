from typing import Dict, Any
import logging
import aiohttp
import json
from datetime import datetime
import asyncio
from urllib.parse import urljoin, urlparse
import networkx as nx
from bs4 import BeautifulSoup, Comment
import re
from functools import reduce
from .base_assistant import BaseAssistant, ReasoningStep, VisualizationType
from .message_bus import MessageType, Message
from .ai_config import AIConfig
from .offensive_tools import OffensiveTools

class AttackStrategist(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__("Attack Strategist", message_bus)
        self.ai_config = AIConfig()
        self.chain = self.ai_config.create_chain("strategist")
        self.discovered_vulnerabilities = []
        self.attack_vectors = []
        self.offensive_tools = OffensiveTools()
        
    async def initialize(self):
        await self.offensive_tools.initialize()
        await self.send_message(
            MessageType.DISCOVERY,
            {"status": "Attack Strategist initialized and ready"},
            priority=3
        )
    
    async def handle_message(self, message: Message):
        if message.sender != self.name:
            if message.type == MessageType.VULNERABILITY:
                await self.process_vulnerability(message.content)
            elif message.type == MessageType.INSIGHT:
                await self.analyze_insight(message.content)
            elif message.type == MessageType.DISCOVERY:
                await self.evaluate_discovery(message.content)
    
    async def process_vulnerability(self, vuln_data):
        self.discovered_vulnerabilities.append(vuln_data)
        
        # Get AI analysis of the vulnerability
        analysis = await self.chain.arun(input=f"Analyze vulnerability: {json.dumps(vuln_data)}")
        analysis_dict = json.loads(analysis) if isinstance(analysis, str) else analysis
        
        strategy = {
            "vulnerability": vuln_data,
            "ai_analysis": analysis_dict,
            "proposed_strategy": "Developing attack strategy based on vulnerability",
            "priority": self.calculate_priority(vuln_data)
        }
        
        await self.send_message(MessageType.STRATEGY, strategy, priority=4)
        
        # Execute attack if vulnerability is high priority
        if self.calculate_priority(vuln_data) >= 4:
            await self.execute_attack(vuln_data)
    
    async def execute_attack(self, vuln_data: Dict[str, Any]):
        """Execute attack based on vulnerability data"""
        try:
            attack_type = vuln_data.get("type", "").lower()
            
            await self.send_message(
                MessageType.ALERT,
                {"status": f"Initiating attack on {attack_type} vulnerability"},
                priority=5
            )
            
            if attack_type == "xss":
                result = await self.offensive_tools.execute_xss_attack(vuln_data)
            elif attack_type == "sql injection":
                result = await self.offensive_tools.execute_sqli_attack(vuln_data)
            elif attack_type == "command injection":
                result = await self.offensive_tools.execute_command_injection(vuln_data)
            else:
                result = await self.offensive_tools.execute_generic_attack(vuln_data)
            
            await self.send_message(
                MessageType.ATTACK_VECTOR,
                {
                    "type": attack_type,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                },
                priority=5
            )
            
        except Exception as e:
            await self.send_message(
                MessageType.ALERT,
                {
                    "error": f"Attack failed: {str(e)}",
                    "vulnerability": vuln_data
                },
                priority=4
            )
    
    async def analyze_insight(self, insight_data):
        analysis = {
            "insight_data": insight_data,
            "strategic_analysis": "Analyzing insight for attack opportunities"
        }
        await self.send_message(MessageType.ATTACK_VECTOR, analysis)
        
        # Check for actionable insights
        if self._is_actionable_insight(insight_data):
            await self.execute_insight_based_attack(insight_data)
    
    def _is_actionable_insight(self, insight_data: Dict[str, Any]) -> bool:
        """Determine if an insight can be acted upon"""
        if not isinstance(insight_data, dict):
            return False
            
        # Check for specific indicators that make an insight actionable
        indicators = [
            "vulnerability_found",
            "attack_surface_detected",
            "weak_configuration",
            "exposed_service"
        ]
        
        return any(indicator in str(insight_data).lower() for indicator in indicators)
    
    async def execute_insight_based_attack(self, insight_data: Dict[str, Any]):
        """Execute attack based on discovered insight"""
        try:
            attack_plan = await self.chain.arun(
                input=f"Develop attack plan for insight: {json.dumps(insight_data)}"
            )
            attack_plan = json.loads(attack_plan) if isinstance(attack_plan, str) else attack_plan
            
            await self.send_message(
                MessageType.STRATEGY,
                {
                    "status": "Executing insight-based attack",
                    "plan": attack_plan
                },
                priority=4
            )
            
            result = await self.offensive_tools.execute_custom_attack(attack_plan)
            
            await self.send_message(
                MessageType.ATTACK_VECTOR,
                {
                    "type": "insight_based",
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                },
                priority=5
            )
            
        except Exception as e:
            await self.send_message(
                MessageType.ALERT,
                {
                    "error": f"Insight-based attack failed: {str(e)}",
                    "insight": insight_data
                },
                priority=4
            )
    
    async def evaluate_discovery(self, discovery_data):
        evaluation = {
            "discovery_data": discovery_data,
            "strategic_evaluation": "Evaluating discovery for potential attack surfaces"
        }
        await self.send_message(MessageType.INSIGHT, evaluation)
    
    def calculate_priority(self, vuln_data):
        severity = vuln_data.get("severity", "LOW")
        priority_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 5}
        return priority_map.get(severity.upper(), 1)
    
    async def shutdown(self):
        await self.send_message(
            MessageType.ALERT,
            {"status": "Attack Strategist shutting down"},
            priority=2
        )

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        strategy = await self.develop_strategy(target, aggressiveness, stealth_mode)
        
        # Execute attacks based on strategy
        attack_results = await self.execute_strategy(strategy, aggressiveness, stealth_mode)
        
        await self.send_message(
            MessageType.STRATEGY,
            {
                "strategy": strategy,
                "attack_results": attack_results
            },
            priority=4
        )
        
        return {
            "status": "completed", 
            "strategy": strategy,
            "attack_results": attack_results
        }

    async def develop_strategy(self, target: str, aggressiveness: int, stealth_mode: bool) -> Dict[str, Any]:
        """Develop attack strategy using LangChain"""
        context = {
            "vulnerabilities": self.discovered_vulnerabilities,
            "attack_vectors": self.attack_vectors
        }
        
        prompt = f"""Develop an attack strategy for {target}
        Aggressiveness Level: {aggressiveness}/10
        Stealth Mode: {'enabled' if stealth_mode else 'disabled'}
        Context: {json.dumps(context)}
        
        Provide:
        1. Attack vector prioritization
        2. Multi-stage attack planning
        3. Risk assessment
        4. Success probability analysis"""
        
        response = await self.chain.arun(input=prompt)
        return json.loads(response) if isinstance(response, str) else response

    async def execute_strategy(self, strategy: Dict[str, Any], aggressiveness: int, stealth_mode: bool) -> Dict[str, Any]:
        """Execute the developed attack strategy"""
        results = {
            "successful_attacks": [],
            "failed_attacks": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Execute attacks in order of priority
            attack_vectors = strategy.get("attack_vectors", [])
            for attack in attack_vectors:
                try:
                    if stealth_mode and attack.get("stealth_compatible", False) == False:
                        continue
                        
                    if attack.get("required_aggressiveness", 5) > aggressiveness:
                        continue
                    
                    result = await self.offensive_tools.execute_attack(
                        attack_type=attack.get("type"),
                        target=attack.get("target"),
                        parameters=attack.get("parameters", {}),
                        options={
                            "stealth_mode": stealth_mode,
                            "aggressiveness": aggressiveness
                        }
                    )
                    
                    if result.get("success", False):
                        results["successful_attacks"].append({
                            "attack": attack,
                            "result": result
                        })
                    else:
                        results["failed_attacks"].append({
                            "attack": attack,
                            "error": result.get("error")
                        })
                        
                except Exception as e:
                    results["failed_attacks"].append({
                        "attack": attack,
                        "error": str(e)
                    })
            
            return results
            
        except Exception as e:
            await self.send_message(
                MessageType.ALERT,
                {
                    "error": f"Strategy execution failed: {str(e)}",
                    "strategy": strategy
                },
                priority=4
            )
            return {"error": str(e)}

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        await self.send_message(
            MessageType.STRATEGY,
            {"status": "Updating attack strategy", "data": strategy_data},
            priority=4
        )