from .base_assistant import BaseAssistant, ReasoningStep, VisualizationType
from typing import Dict, Any, List
import logging
import aiohttp
import ssl
import socket
from urllib.parse import urlparse
import json
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from bs4 import BeautifulSoup

class SecurityTools(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.session = None
        self.current_scan_id = None
        self.vulnerability_graph = nx.DiGraph()
        self.scan_history = []

    async def initialize(self):
        """Initialize security tools and connections"""
        self.session = aiohttp.ClientSession()
        
        # Log initialization with visualization
        init_step = ReasoningStep(
            step_id="security_init",
            description="Initializing security analysis components",
            visualization_type=VisualizationType.DEPENDENCY_MAP,
            data=self._get_component_dependencies()
        )
        await self.log_reasoning_step(init_step)
        
        # Share initialization status
        await self.publish_discovery({
            "component": "security_tools",
            "status": "initialized",
            "capabilities": self._get_security_capabilities()
        })

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run security analysis"""
        try:
            self.current_scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Initial security assessment visualization
            assessment_step = ReasoningStep(
                step_id=f"{self.current_scan_id}_initial_assessment",
                description="Starting security assessment",
                visualization_type=VisualizationType.ATTACK_GRAPH,
                data={"target": target, "mode": "initial"}
            )
            await self.log_reasoning_step(assessment_step)

            results = {
                "ssl_analysis": await self.analyze_ssl(target),
                "headers_analysis": await self.analyze_headers(target),
                "vulnerability_scan": await self.scan_vulnerabilities(target, aggressiveness),
                "security_posture": await self.assess_security_posture(target)
            }
            
            if aggressiveness > 3 and not stealth_mode:
                deep_scan_step = ReasoningStep(
                    step_id=f"{self.current_scan_id}_deep_scan",
                    description="Performing deep security analysis",
                    visualization_type=VisualizationType.VULNERABILITY_MATRIX,
                    data={"scan_type": "deep", "target": target}
                )
                await self.log_reasoning_step(deep_scan_step)
                
                results.update({
                    "deep_scan": await self.deep_security_scan(target),
                    "compliance_check": await self.check_compliance(target)
                })
            
            # Final analysis visualization
            final_step = ReasoningStep(
                step_id=f"{self.current_scan_id}_final",
                description="Security assessment complete",
                visualization_type=VisualizationType.HEATMAP,
                data=self._prepare_results_visualization(results)
            )
            await self.log_reasoning_step(final_step)
            
            return results
            
        except Exception as e:
            error_step = ReasoningStep(
                step_id=f"{self.current_scan_id}_error",
                description=f"Error in security analysis: {str(e)}",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"error": str(e), "state": "failed"}
            )
            await self.log_reasoning_step(error_step)
            raise

    async def analyze_ssl(self, target: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        try:
            hostname = urlparse(target).netloc or target
            context = ssl.create_default_context()
            
            ssl_step = ReasoningStep(
                step_id=f"{self.current_scan_id}_ssl",
                description="Analyzing SSL/TLS configuration",
                visualization_type=VisualizationType.NETWORK_MAP,
                data={"target": hostname, "type": "ssl_analysis"}
            )
            await self.log_reasoning_step(ssl_step)
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    results = {
                        "certificate": {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "version": cert['version'],
                            "expires": cert['notAfter'],
                            "issued": cert['notBefore']
                        },
                        "cipher": {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        }
                    }
                    
                    # Visualize SSL findings
                    ssl_results_step = ReasoningStep(
                        step_id=f"{self.current_scan_id}_ssl_results",
                        description="SSL/TLS Analysis Results",
                        visualization_type=VisualizationType.DEPENDENCY_MAP,
                        data=results
                    )
                    await self.log_reasoning_step(ssl_results_step)
                    
                    return results
                    
        except Exception as e:
            await self.publish_alert({
                "type": "ssl_error",
                "target": target,
                "error": str(e),
                "priority": 4
            })
            return {"error": str(e)}

    async def analyze_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        security_headers = {
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        }
        
        headers_step = ReasoningStep(
            step_id=f"{self.current_scan_id}_headers",
            description="Analyzing security headers",
            visualization_type=VisualizationType.HEATMAP,
            data={"target": target, "type": "header_analysis"}
        )
        await self.log_reasoning_step(headers_step)
        
        async with self.session.get(target) as response:
            headers = response.headers
            results = {
                "present": {h: headers.get(h) for h in security_headers if h in headers},
                "missing": list(security_headers - headers.keys())
            }
            
            if results["missing"]:
                await self.publish_vulnerability({
                    "type": "missing_security_headers",
                    "missing": results["missing"],
                    "severity": "medium",
                    "priority": 3
                })
            
            return results

    async def scan_vulnerabilities(self, target: str, aggressiveness: int) -> Dict[str, Any]:
        """Scan for vulnerabilities"""
        scan_step = ReasoningStep(
            step_id=f"{self.current_scan_id}_vuln_scan",
            description="Scanning for vulnerabilities",
            visualization_type=VisualizationType.ATTACK_GRAPH,
            data={"target": target, "aggressiveness": aggressiveness}
        )
        await self.log_reasoning_step(scan_step)
        
        vulnerabilities = []
        
        async with self.session.get(target) as response:
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Basic security checks
            basic_vulns = await self._check_basic_vulnerabilities(soup)
            vulnerabilities.extend(basic_vulns)
            
            if aggressiveness > 3:
                # Advanced vulnerability checks
                advanced_vulns = await self._check_advanced_vulnerabilities(soup, target)
                vulnerabilities.extend(advanced_vulns)
            
            # Visualize findings
            findings_step = ReasoningStep(
                step_id=f"{self.current_scan_id}_vuln_findings",
                description="Vulnerability Scan Results",
                visualization_type=VisualizationType.VULNERABILITY_MATRIX,
                data={"vulnerabilities": vulnerabilities}
            )
            await self.log_reasoning_step(findings_step)
            
            return {"findings": vulnerabilities}

    async def assess_security_posture(self, target: str) -> Dict[str, Any]:
        """Assess overall security posture"""
        posture_step = ReasoningStep(
            step_id=f"{self.current_scan_id}_posture",
            description="Assessing security posture",
            visualization_type=VisualizationType.HEATMAP,
            data={"target": target, "type": "posture_assessment"}
        )
        await self.log_reasoning_step(posture_step)
        
        async with self.session.get(target) as response:
            headers = response.headers
            cookies = response.cookies
            
            assessment = {
                "headers_score": self._calculate_header_score(headers),
                "cookie_security": self._analyze_cookies(cookies),
                "transport_security": self._check_transport_security(headers)
            }
            
            # Share findings
            if assessment["headers_score"] < 0.6:
                await self.publish_vulnerability({
                    "type": "weak_security_headers",
                    "score": assessment["headers_score"],
                    "severity": "medium",
                    "priority": 3
                })
            
            return assessment

    def _get_component_dependencies(self) -> Dict[str, Any]:
        """Get security component dependencies for visualization"""
        return {
            "nodes": [
                {"id": "ssl", "type": "analyzer"},
                {"id": "headers", "type": "analyzer"},
                {"id": "vulnerabilities", "type": "scanner"},
                {"id": "posture", "type": "assessor"}
            ],
            "edges": [
                {"source": "ssl", "target": "posture"},
                {"source": "headers", "target": "posture"},
                {"source": "vulnerabilities", "target": "posture"}
            ]
        }

    def _get_security_capabilities(self) -> List[str]:
        """Get list of security capabilities"""
        return [
            "SSL/TLS Analysis",
            "Security Headers Assessment",
            "Vulnerability Scanning",
            "Security Posture Assessment",
            "Compliance Checking",
            "Deep Security Analysis"
        ]

    def _prepare_results_visualization(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for visualization"""
        return {
            "findings": results,
            "metrics": {
                "vulnerabilities": len(results.get("vulnerability_scan", {}).get("findings", [])),
                "security_score": self._calculate_security_score(results),
                "risk_level": self._determine_risk_level(results)
            }
        }

    async def _check_basic_vulnerabilities(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for basic vulnerabilities"""
        vulns = []
        
        # Check for common security issues
        if forms := soup.find_all('form'):
            for form in forms:
                if not form.get('action', '').startswith('https'):
                    vulns.append({
                        "type": "insecure_form",
                        "severity": "high",
                        "location": str(form.get('action')),
                        "description": "Form submits data over insecure HTTP"
                    })
        
        return vulns

    async def _check_advanced_vulnerabilities(self, soup: BeautifulSoup, target: str) -> List[Dict[str, Any]]:
        """Check for advanced vulnerabilities"""
        vulns = []
        
        # Advanced checks implementation
        # ... (implementation details)
        
        return vulns

    def _calculate_security_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall security score"""
        # Score calculation implementation
        return 0.0

    def _determine_risk_level(self, results: Dict[str, Any]) -> str:
        """Determine overall risk level"""
        # Risk level determination implementation
        return "medium"

    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update security analysis strategy"""
        strategy_step = ReasoningStep(
            step_id=f"{self.current_scan_id}_strategy_update",
            description="Updating security strategy",
            visualization_type=VisualizationType.FLOW_DIAGRAM,
            data=strategy_data
        )
        await self.log_reasoning_step(strategy_step)