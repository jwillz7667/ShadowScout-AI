from .base_assistant import BaseAssistant
from typing import Dict, Any, List
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import logging
import json

class BrowserAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.browser = None
        self.context = None
        self.page = None

    async def initialize(self):
        """Initialize browser automation"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        self.page = await self.context.new_page()

        await self.publish_discovery({
            "component": "browser_assistant",
            "status": "initialized",
            "capabilities": ["DOM analysis", "JavaScript inspection", "Network monitoring"]
        })

    async def close(self):
        """Cleanup browser resources"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run browser-based analysis"""
        try:
            # Navigate to target
            await self.page.goto(target)
            
            # Collect initial findings
            findings = {
                "dom_analysis": await self._analyze_dom(),
                "javascript_analysis": await self._analyze_javascript(),
                "network_analysis": await self._analyze_network(),
                "security_headers": await self._analyze_security_headers()
            }

            # Share discoveries with other assistants
            await self.publish_discovery({
                "type": "initial_analysis",
                "target": target,
                "findings": findings
            })

            # Look for potential vulnerabilities
            vulnerabilities = await self._check_vulnerabilities()
            if vulnerabilities:
                await self.publish_vulnerability({
                    "source": "browser_analysis",
                    "findings": vulnerabilities,
                    "severity": "medium"
                })

            # If aggressive mode, perform deeper analysis
            if aggressiveness > 3 and not stealth_mode:
                advanced_findings = await self._perform_advanced_analysis()
                findings.update(advanced_findings)

            return findings

        except Exception as e:
            await self.publish_alert({
                "type": "error",
                "component": "browser_assistant",
                "message": str(e)
            })
            raise

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update browser analysis strategy based on new information"""
        if "focus_areas" in strategy_data:
            await self._adjust_analysis_focus(strategy_data["focus_areas"])

    async def _analyze_dom(self) -> Dict[str, Any]:
        """Analyze DOM structure"""
        dom_content = await self.page.content()
        soup = BeautifulSoup(dom_content, 'html.parser')
        
        analysis = {
            "forms": len(soup.find_all('form')),
            "inputs": len(soup.find_all('input')),
            "links": len(soup.find_all('a')),
            "scripts": len(soup.find_all('script')),
            "iframes": len(soup.find_all('iframe'))
        }

        # Share interesting DOM findings
        if analysis["forms"] > 0 or analysis["inputs"] > 0:
            await self.publish_discovery({
                "type": "dom_elements",
                "elements": analysis,
                "priority": 3
            })

        return analysis

    async def _analyze_javascript(self) -> Dict[str, Any]:
        """Analyze JavaScript code"""
        scripts = await self.page.evaluate("""
            Array.from(document.scripts).map(script => ({
                src: script.src,
                content: script.text.substring(0, 500),
                type: script.type
            }))
        """)

        # Look for sensitive patterns
        sensitive_patterns = ['password', 'token', 'api', 'key', 'secret']
        for script in scripts:
            for pattern in sensitive_patterns:
                if pattern in script.get('content', '').lower():
                    await self.publish_alert({
                        "type": "sensitive_data",
                        "location": "javascript",
                        "pattern": pattern,
                        "priority": 4
                    })

        return {"scripts": scripts}

    async def _analyze_network(self) -> Dict[str, Any]:
        """Analyze network traffic"""
        network_data = []
        
        async def handle_request(request):
            data = {
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
                "resource_type": request.resource_type
            }
            network_data.append(data)
            
            # Check for sensitive information in requests
            if any(sensitive in request.url.lower() for sensitive in ['admin', 'login', 'api']):
                await self.publish_discovery({
                    "type": "sensitive_endpoint",
                    "url": request.url,
                    "method": request.method,
                    "priority": 4
                })

        self.page.on('request', handle_request)
        
        # Wait for network idle
        await self.page.wait_for_load_state('networkidle')
        
        return {"network_requests": network_data}

    async def _analyze_security_headers(self) -> Dict[str, Any]:
        """Analyze security headers"""
        response = await self.page.goto(self.page.url)
        headers = response.headers
        
        security_headers = {
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Strict-Transport-Security'
        }
        
        missing_headers = security_headers - set(headers.keys())
        if missing_headers:
            await self.publish_vulnerability({
                "type": "missing_security_headers",
                "missing": list(missing_headers),
                "severity": "medium",
                "priority": 3
            })

        return {
            "security_headers": {k: v for k, v in headers.items() if k in security_headers},
            "missing_headers": list(missing_headers)
        }

    async def _check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for XSS vulnerabilities
        xss_vulns = await self._check_xss_vulnerabilities()
        if xss_vulns:
            vulnerabilities.extend(xss_vulns)
            await self.publish_vulnerability({
                "type": "xss",
                "findings": xss_vulns,
                "severity": "high",
                "priority": 5
            })

        # Check for open redirects
        redirect_vulns = await self._check_open_redirects()
        if redirect_vulns:
            vulnerabilities.extend(redirect_vulns)
            await self.publish_vulnerability({
                "type": "open_redirect",
                "findings": redirect_vulns,
                "severity": "medium",
                "priority": 3
            })

        return vulnerabilities

    async def _perform_advanced_analysis(self) -> Dict[str, Any]:
        """Perform advanced analysis"""
        advanced_findings = {}
        
        # Analyze client-side storage
        storage = await self._analyze_client_storage()
        advanced_findings["client_storage"] = storage
        
        # Check for DOM-based vulnerabilities
        dom_vulns = await self._check_dom_vulnerabilities()
        advanced_findings["dom_vulnerabilities"] = dom_vulns
        
        # Analyze event handlers
        events = await self._analyze_event_handlers()
        advanced_findings["event_handlers"] = events
        
        return advanced_findings

    async def _adjust_analysis_focus(self, focus_areas: List[str]):
        """Adjust analysis focus based on strategy"""
        # Implementation specific to browser analysis
        pass

    # Additional helper methods...