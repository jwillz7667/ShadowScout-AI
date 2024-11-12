from typing import Optional, Dict
import asyncio
import aiohttp
from config.config import Config

class SecurityScanner:
    def __init__(self):
        self.api_key = Config.SECURITY_SETTINGS['api_key']
        self.base_url = Config.SECURITY_SETTINGS['api_endpoint']
        
    async def scan_url(self, url: str) -> Dict:
        """Scan a URL for security vulnerabilities."""
        async with aiohttp.ClientSession() as session:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            async with session.post(
                f'{self.base_url}/scan',
                json={'url': url},
                headers=headers
            ) as response:
                return await response.json()
    
    async def analyze_vulnerability(self, scan_result: Dict) -> str:
        """Analyze vulnerability scan results and provide recommendations."""
        if not scan_result.get('vulnerabilities'):
            return "No vulnerabilities detected."
            
        analysis = []
        for vuln in scan_result['vulnerabilities']:
            analysis.append(f"- {vuln['severity'].upper()}: {vuln['title']}\n"
                          f"  Description: {vuln['description']}\n"
                          f"  Recommendation: {vuln['recommendation']}")
        
        return "\n\n".join(analysis) 