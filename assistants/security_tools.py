import asyncio
import subprocess
import aiohttp
import json
from typing import Dict, Optional, List
from pathlib import Path
from config.config import Config
import dns.resolver
import whois
from bs4 import BeautifulSoup

class SecurityTools:
    def __init__(self):
        self.output_dir = Path(Config.SECURITY_SETTINGS['output_dir'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = aiohttp.ClientSession()
    
    async def run_passive_scan(self, url: str) -> str:
        """Perform passive reconnaissance without active scanning."""
        try:
            results = {
                "whois": await self._get_whois_info(url),
                "dns": await self._get_dns_info(url),
                "headers": await self.analyze_headers(url),
                "technologies": await self.detect_technologies(url)
            }
            return json.dumps(results, indent=2)
        except Exception as e:
            return f"Error during passive scan: {str(e)}"

    async def analyze_headers(self, url: str) -> Dict:
        """Analyze HTTP headers for security configurations."""
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                security_headers = {
                    "Security Headers": {
                        "X-Frame-Options": headers.get("X-Frame-Options", "Not Set"),
                        "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Set"),
                        "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Set"),
                        "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Set"),
                        "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Set")
                    },
                    "Server Info": {
                        "Server": headers.get("Server", "Not Disclosed"),
                        "X-Powered-By": headers.get("X-Powered-By", "Not Disclosed")
                    }
                }
                return security_headers
        except Exception as e:
            return {"error": f"Header analysis failed: {str(e)}"}

    async def detect_technologies(self, url: str) -> Dict:
        """Detect technologies used by the website through passive means."""
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                technologies = {
                    "JavaScript Frameworks": await self._detect_js_frameworks(soup),
                    "Web Servers": await self._detect_web_server(response.headers),
                    "CMS": await self._detect_cms(soup),
                    "Analytics": await self._detect_analytics(soup),
                    "Security": await self._detect_security_solutions(response.headers)
                }
                return technologies
        except Exception as e:
            return {"error": f"Technology detection failed: {str(e)}"}

    async def _get_whois_info(self, url: str) -> Dict:
        """Get WHOIS information for the domain."""
        try:
            domain = url.split("://")[-1].split("/")[0]
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    async def _get_dns_info(self, url: str) -> Dict:
        """Get DNS information for the domain."""
        try:
            domain = url.split("://")[-1].split("/")[0]
            records = {
                "A": await self._resolve_dns(domain, "A"),
                "MX": await self._resolve_dns(domain, "MX"),
                "NS": await self._resolve_dns(domain, "NS"),
                "TXT": await self._resolve_dns(domain, "TXT")
            }
            return records
        except Exception as e:
            return {"error": f"DNS lookup failed: {str(e)}"}

    async def _resolve_dns(self, domain: str, record_type: str) -> List[str]:
        """Resolve DNS records of specified type."""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def _detect_js_frameworks(self, soup: BeautifulSoup) -> List[str]:
        """Detect JavaScript frameworks used on the page."""
        frameworks = []
        scripts = soup.find_all("script", src=True)
        
        for script in scripts:
            src = script["src"].lower()
            if "react" in src: frameworks.append("React")
            elif "vue" in src: frameworks.append("Vue.js")
            elif "angular" in src: frameworks.append("Angular")
            elif "jquery" in src: frameworks.append("jQuery")
        
        return list(set(frameworks))

    async def _detect_web_server(self, headers: Dict) -> str:
        """Detect web server from headers."""
        return headers.get("Server", "Unknown")

    async def _detect_cms(self, soup: BeautifulSoup) -> List[str]:
        """Detect Content Management Systems."""
        cms = []
        
        # WordPress detection
        if soup.find("meta", {"name": "generator", "content": lambda x: x and "WordPress" in x}):
            cms.append("WordPress")
        
        # Drupal detection
        if soup.find("meta", {"name": "Generator", "content": lambda x: x and "Drupal" in x}):
            cms.append("Drupal")
        
        return cms

    async def _detect_analytics(self, soup: BeautifulSoup) -> List[str]:
        """Detect analytics tools."""
        analytics = []
        
        if soup.find("script", src=lambda x: x and "google-analytics.com" in x):
            analytics.append("Google Analytics")
        
        if soup.find("script", src=lambda x: x and "hotjar.com" in x):
            analytics.append("Hotjar")
        
        return analytics

    async def _detect_security_solutions(self, headers: Dict) -> List[str]:
        """Detect security solutions from headers."""
        solutions = []
        
        if "cf-ray" in headers:
            solutions.append("Cloudflare")
        if "x-sucuri-id" in headers:
            solutions.append("Sucuri")
        if "x-fw-server" in headers:
            solutions.append("Firewall Present")
        
        return solutions

    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()