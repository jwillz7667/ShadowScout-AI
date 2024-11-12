import asyncio
import subprocess
import aiohttp
import json
from typing import Dict, Optional, List, Tuple
from pathlib import Path
from config.config import Config
import dns.resolver
import whois
from bs4 import BeautifulSoup
import ssl
import socket
import re
from urllib.parse import urlparse, urljoin

class SecurityTools:
    def __init__(self):
        self.output_dir = Path(Config.SECURITY_SETTINGS['output_dir'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = aiohttp.ClientSession()
        self.scan_history = []
        self.discovered_endpoints = set()
        
    async def run_passive_scan(self, url: str) -> str:
        """Enhanced passive reconnaissance."""
        try:
            base_domain = urlparse(url).netloc
            results = {
                "whois": await self._get_whois_info(url),
                "dns": await self._get_dns_info(url),
                "headers": await self.analyze_headers(url),
                "technologies": await self.detect_technologies(url),
                "ssl_info": await self._get_ssl_info(base_domain),
                "endpoints": await self._discover_endpoints(url),
                "subdomains": await self._enumerate_subdomains(base_domain),
                "email_addresses": await self._find_email_addresses(url),
                "social_media": await self._find_social_media(url),
                "exposed_files": await self._check_exposed_files(url)
            }
            self.scan_history.append({
                "timestamp": asyncio.get_event_loop().time(),
                "url": url,
                "findings": results
            })
            return json.dumps(results, indent=2)
        except Exception as e:
            return f"Error during passive scan: {str(e)}"

    async def _get_ssl_info(self, domain: str) -> Dict:
        """Get detailed SSL certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "version": cert['version'],
                        "serialNumber": cert['serialNumber'],
                        "notBefore": cert['notBefore'],
                        "notAfter": cert['notAfter'],
                        "subjectAltName": cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {"error": f"SSL analysis failed: {str(e)}"}

    async def _discover_endpoints(self, url: str) -> List[str]:
        """Discover endpoints through passive means."""
        discovered = set()
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find links
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    full_url = urljoin(url, href)
                    if url in full_url and full_url not in discovered:
                        discovered.add(full_url)
                
                # Find forms
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    full_url = urljoin(url, action)
                    if url in full_url:
                        discovered.add(full_url)
                
                # Find API endpoints
                api_patterns = [
                    r'/api/[\w/]+',
                    r'/v\d+/[\w/]+',
                    r'/rest/[\w/]+',
                    r'/graphql'
                ]
                for pattern in api_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        full_url = urljoin(url, match)
                        discovered.add(full_url)
                
                self.discovered_endpoints.update(discovered)
                return list(discovered)
        except Exception as e:
            return [f"Endpoint discovery failed: {str(e)}"]

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains through DNS and other passive means."""
        subdomains = set()
        try:
            # Check common subdomains
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api']
            for sub in common_subdomains:
                try:
                    answers = dns.resolver.resolve(f"{sub}.{domain}", "A")
                    if answers:
                        subdomains.add(f"{sub}.{domain}")
                except:
                    continue
                    
            # Check DNS TXT records for additional subdomains
            try:
                txt_records = await self._resolve_dns(domain, "TXT")
                for record in txt_records:
                    matches = re.findall(r'[a-zA-Z0-9.-]+\.' + domain, record)
                    subdomains.update(matches)
            except:
                pass
                
            return list(subdomains)
        except Exception as e:
            return [f"Subdomain enumeration failed: {str(e)}"]

    async def _find_email_addresses(self, url: str) -> List[str]:
        """Find email addresses through passive means."""
        emails = set()
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                found_emails = re.findall(email_pattern, content)
                emails.update(found_emails)
                return list(emails)
        except Exception as e:
            return [f"Email discovery failed: {str(e)}"]

    async def _find_social_media(self, url: str) -> Dict[str, str]:
        """Find social media links and profiles."""
        social_media = {}
        platforms = {
            'facebook': r'facebook\.com/[\w.]+',
            'twitter': r'twitter\.com/[\w]+',
            'linkedin': r'linkedin\.com/[\w/]+',
            'instagram': r'instagram\.com/[\w.]+',
            'github': r'github\.com/[\w-]+'
        }
        
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                for platform, pattern in platforms.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        social_media[platform] = list(set(matches))
                return social_media
        except Exception as e:
            return {"error": f"Social media discovery failed: {str(e)}"}

    async def _check_exposed_files(self, url: str) -> List[str]:
        """Check for exposed sensitive files."""
        sensitive_files = [
            'robots.txt',
            '.git/HEAD',
            'sitemap.xml',
            '.env',
            'backup.zip',
            'wp-config.php',
            '.htaccess',
            'crossdomain.xml',
            'phpinfo.php'
        ]
        
        exposed = []
        for file in sensitive_files:
            try:
                file_url = urljoin(url, file)
                async with self.session.get(file_url) as response:
                    if response.status == 200:
                        exposed.append(file_url)
            except:
                continue
        return exposed

    async def get_scan_summary(self) -> Dict:
        """Get summary of all scan results."""
        return {
            "total_scans": len(self.scan_history),
            "discovered_endpoints": len(self.discovered_endpoints),
            "last_scan": self.scan_history[-1] if self.scan_history else None,
            "unique_technologies": self._get_unique_technologies(),
            "security_score": await self._calculate_security_score()
        }

    def _get_unique_technologies(self) -> List[str]:
        """Get list of unique technologies found across all scans."""
        technologies = set()
        for scan in self.scan_history:
            if 'technologies' in scan['findings']:
                for tech_type, techs in scan['findings']['technologies'].items():
                    if isinstance(techs, list):
                        technologies.update(techs)
                    elif isinstance(techs, str):
                        technologies.add(techs)
        return list(technologies)

    async def _calculate_security_score(self) -> int:
        """Calculate security score based on findings."""
        score = 100
        if self.scan_history:
            latest_scan = self.scan_history[-1]['findings']
            
            # Check security headers
            headers = latest_scan.get('headers', {}).get('Security Headers', {})
            for header, value in headers.items():
                if value == "Not Set":
                    score -= 5
            
            # Check SSL
            ssl_info = latest_scan.get('ssl_info', {})
            if 'error' in ssl_info:
                score -= 10
            
            # Check exposed files
            exposed_files = latest_scan.get('exposed_files', [])
            score -= len(exposed_files) * 5
            
            # Ensure score stays within bounds
            return max(0, min(score, 100))
        return 0

    async def close(self):
        """Cleanup resources and save scan history."""
        if self.session and not self.session.closed:
            await self.session.close()
        
        # Save scan history
        history_file = self.output_dir / "scan_history.json"
        with open(history_file, 'w') as f:
            json.dump(self.scan_history, f, indent=2)

    async def _get_whois_info(self, url: str) -> Dict:
        """Get WHOIS information."""
        try:
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    async def detect_technologies(self, url: str) -> Dict:
        """Detect technologies used by the website."""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                technologies = {
                    "server": response.headers.get('Server', 'Unknown'),
                    "frameworks": await self._detect_frameworks(soup),
                    "cms": await self._detect_cms(soup),
                    "analytics": await self._detect_analytics(soup)
                }
                return technologies
        except Exception as e:
            return {"error": f"Technology detection failed: {str(e)}"}