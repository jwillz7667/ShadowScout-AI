import json
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class VulnerabilityVector:
    name: str
    severity: str
    description: str
    attack_path: List[str]
    success_rate: float

class AttackStrategist:
    def __init__(self):
        self.vulnerability_vectors = []
        self.attack_paths = []
        
    async def analyze_scan_results(self, scan_results: Dict) -> str:
        """Analyze scan results and identify potential attack vectors."""
        try:
            vectors = []
            
            # Analyze security headers
            if "headers" in scan_results:
                vectors.extend(await self._analyze_security_headers(scan_results["headers"]))
            
            # Analyze detected technologies
            if "technologies" in scan_results:
                vectors.extend(await self._analyze_tech_stack(scan_results["technologies"]))
            
            # Analyze infrastructure
            if "dns" in scan_results:
                vectors.extend(await self._analyze_infrastructure(scan_results["dns"]))
            
            self.vulnerability_vectors = vectors
            return await self._generate_attack_strategy()
        except Exception as e:
            return f"Error analyzing results: {str(e)}"

    async def _analyze_security_headers(self, headers: Dict) -> List[VulnerabilityVector]:
        """Analyze security headers for potential vulnerabilities."""
        vectors = []
        security_headers = headers.get("Security Headers", {})
        
        # Check for missing security headers
        if security_headers.get("X-Frame-Options") == "Not Set":
            vectors.append(VulnerabilityVector(
                name="Clickjacking Potential",
                severity="Medium",
                description="X-Frame-Options header not set",
                attack_path=["Frame Injection", "UI Redressing"],
                success_rate=0.7
            ))
            
        if security_headers.get("Content-Security-Policy") == "Not Set":
            vectors.append(VulnerabilityVector(
                name="XSS Vulnerability",
                severity="High",
                description="No Content Security Policy",
                attack_path=["Script Injection", "Data Exfiltration"],
                success_rate=0.8
            ))
            
        return vectors

    async def _analyze_tech_stack(self, technologies: Dict) -> List[VulnerabilityVector]:
        """Analyze technology stack for known vulnerabilities."""
        vectors = []
        
        for framework in technologies.get("JavaScript Frameworks", []):
            if framework.lower() == "jquery":
                vectors.append(VulnerabilityVector(
                    name="jQuery Version Analysis",
                    severity="Medium",
                    description="Potential outdated jQuery version",
                    attack_path=["Version Fingerprinting", "Known Vulnerability Exploitation"],
                    success_rate=0.6
                ))
                
        for cms in technologies.get("CMS", []):
            if cms.lower() == "wordpress":
                vectors.append(VulnerabilityVector(
                    name="WordPress Component Analysis",
                    severity="High",
                    description="WordPress installation detected",
                    attack_path=["Plugin Enumeration", "Theme Analysis", "Version Exploitation"],
                    success_rate=0.75
                ))
                
        return vectors

    async def _analyze_infrastructure(self, dns_info: Dict) -> List[VulnerabilityVector]:
        """Analyze infrastructure for potential attack vectors."""
        vectors = []
        
        if dns_info.get("A"):
            vectors.append(VulnerabilityVector(
                name="Infrastructure Analysis",
                severity="Medium",
                description="Direct IP exposure",
                attack_path=["Server Fingerprinting", "Service Enumeration"],
                success_rate=0.65
            ))
            
        return vectors

    async def _generate_attack_strategy(self) -> str:
        """Generate comprehensive attack strategy based on discovered vectors."""
        if not self.vulnerability_vectors:
            return "No significant attack vectors identified."
            
        # Sort vectors by success rate and severity
        sorted_vectors = sorted(
            self.vulnerability_vectors,
            key=lambda x: (x.success_rate, x.severity == "High"),
            reverse=True
        )
        
        strategy = "Attack Strategy Analysis:\n\n"
        for i, vector in enumerate(sorted_vectors, 1):
            strategy += f"{i}. {vector.name} (Success Rate: {vector.success_rate*100}%)\n"
            strategy += f"   Severity: {vector.severity}\n"
            strategy += f"   Description: {vector.description}\n"
            strategy += f"   Attack Path: {' -> '.join(vector.attack_path)}\n\n"
            
        return strategy

    async def get_attack_recommendations(self) -> str:
        """Get prioritized attack recommendations."""
        if not self.vulnerability_vectors:
            return "No attack vectors to analyze."
            
        high_priority = [v for v in self.vulnerability_vectors if v.severity == "High"]
        medium_priority = [v for v in self.vulnerability_vectors if v.severity == "Medium"]
        
        recommendations = "Priority Attack Vectors:\n\n"
        
        if high_priority:
            recommendations += "High Priority:\n"
            for vector in high_priority:
                recommendations += f"- {vector.name}: {vector.description}\n"
                
        if medium_priority:
            recommendations += "\nMedium Priority:\n"
            for vector in medium_priority:
                recommendations += f"- {vector.name}: {vector.description}\n"
                
        return recommendations 