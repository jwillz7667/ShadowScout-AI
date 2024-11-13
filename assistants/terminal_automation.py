import asyncio
import subprocess
from typing import Dict, Any, List, Optional
import logging
import json
import re
from pathlib import Path
import aiofiles
import nmap
import socket
import os
import sys
import ctypes
from datetime import datetime
import aiohttp
from scapy.all import conf, sr1, traceroute
from scapy.layers.inet import IP, TCP
import netifaces

class TerminalAutomation:
    def __init__(self):
        self.logger = logging.getLogger("TerminalAutomation")
        self.nmap_scanner = nmap.PortScanner()
        self.output_dir = Path(os.getenv('SECURITY_SCAN_OUTPUT_DIR', 'scan_results'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Check and request root/admin privileges
        if not self.check_privileges():
            self.request_privileges()
        
        # Configure Scapy to be quiet about interface warnings
        conf.verb = 0
        
        # Get the default interface that has an IPv4 address
        self.default_interface = self._get_default_interface()

    def _get_default_interface(self) -> str:
        """Get the default network interface with an IPv4 address"""
        try:
            # First try to get the default route interface
            gws = netifaces.gateways()
            default_iface = gws.get('default', {}).get(netifaces.AF_INET, [None, None])[1]
            if default_iface and self._interface_has_ipv4(default_iface):
                return default_iface

            # If no default route or it doesn't have IPv4, try all interfaces
            for iface in netifaces.interfaces():
                if self._interface_has_ipv4(iface):
                    return iface

            # If still no interface found, return the first available interface
            return netifaces.interfaces()[0]

        except Exception as e:
            self.logger.error(f"Error getting default interface: {e}")
            return conf.iface  # Fallback to Scapy's default

    def _interface_has_ipv4(self, interface: str) -> bool:
        """Check if interface has an IPv4 address"""
        try:
            addrs = netifaces.ifaddresses(interface)
            return netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]
        except Exception:
            return False

    def check_privileges(self) -> bool:
        """Check if script has root/admin privileges"""
        try:
            if os.name == 'nt':  # Windows
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix/Linux/MacOS
                return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"Error checking privileges: {e}")
            return False

    def request_privileges(self):
        """Request root/admin privileges"""
        try:
            if os.name == 'nt':  # Windows
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    # Re-run the program with admin rights
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                    sys.exit()
            else:  # Unix/Linux/MacOS
                if os.geteuid() != 0:
                    # Re-run the program with sudo
                    args = ['sudo', sys.executable] + sys.argv
                    os.execvp('sudo', args)
        except Exception as e:
            self.logger.error(f"Error requesting privileges: {e}")
            raise PermissionError("Root/admin privileges are required for scanning operations")

    async def run_privileged_command(self, command: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Run a command with elevated privileges"""
        try:
            if not self.check_privileges():
                if os.name == 'nt':  # Windows
                    command.insert(0, 'runas')
                else:  # Unix/Linux/MacOS
                    command.insert(0, 'sudo')
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
            
            return {
                "command": " ".join(command),
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "return_code": process.returncode
            }
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds: {command}")
            return {"error": "Command timed out", "command": " ".join(command)}
        except Exception as e:
            self.logger.error(f"Error running privileged command {command}: {str(e)}")
            return {"error": str(e), "command": " ".join(command)}

    async def port_scan(self, target: str, aggressive: bool = False) -> Dict[str, Any]:
        """Perform port scanning using nmap with elevated privileges"""
        if not self.check_privileges():
            self.logger.error("Root/admin privileges required for port scanning")
            raise PermissionError("Root/admin privileges required for port scanning")
            
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            
            # Configure scan arguments
            arguments = '-sS -sV -sC' if aggressive else '-sS -sV'
            
            # Run nmap scan with elevated privileges
            if os.name == 'nt':  # Windows
                self.nmap_scanner.scan(ip, arguments=arguments, sudo=False)  # nmap requires admin shell on Windows
            else:  # Unix/Linux/MacOS
                self.nmap_scanner.scan(ip, arguments=arguments, sudo=True)
            
            # Process results
            results = {
                "target": target,
                "ip": ip,
                "ports": [],
                "os_matches": [],
                "services": []
            }
            
            for host in self.nmap_scanner.all_hosts():
                for proto in self.nmap_scanner[host].all_protocols():
                    ports = self.nmap_scanner[host][proto].keys()
                    for port in ports:
                        port_info = self.nmap_scanner[host][proto][port]
                        results["ports"].append({
                            "port": port,
                            "state": port_info.get("state"),
                            "service": port_info.get("name"),
                            "version": port_info.get("version"),
                            "product": port_info.get("product")
                        })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Port scan error: {str(e)}")
            return {"error": str(e)}

    async def vulnerability_scan(self, target: str, aggressive: bool = False) -> Dict[str, Any]:
        """Perform vulnerability scanning"""
        results = {
            "target": target,
            "vulnerabilities": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Basic SSL/TLS scan
            ssl_scan = await self.run_command([
                "openssl", "s_client", "-connect", f"{target}:443",
                "-status", "-tlsextdebug"
            ])
            if ssl_scan.get("return_code") == 0:
                results["ssl_scan"] = self._parse_ssl_output(ssl_scan["stdout"])
            
            # DNS enumeration
            dns_scan = await self.run_command([
                "dig", "+short", target
            ])
            results["dns_info"] = self._parse_dns_output(dns_scan["stdout"])
            
            # If aggressive, perform more intensive scans
            if aggressive:
                # Directory enumeration
                dir_scan = await self.run_command([
                    "gobuster", "dir",
                    "-u", f"https://{target}",
                    "-w", "/usr/share/wordlists/dirb/common.txt"
                ])
                results["directory_scan"] = self._parse_gobuster_output(dir_scan["stdout"])
                
                # WordPress scan if detected
                if await self._is_wordpress(target):
                    wp_scan = await self.run_command([
                        "wpscan",
                        "--url", f"https://{target}",
                        "--api-token", os.getenv('WPSCAN_API_KEY', '')
                    ])
                    results["wordpress_scan"] = self._parse_wpscan_output(wp_scan["stdout"])
            
            return results
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
            return {"error": str(e)}

    async def _is_wordpress(self, target: str) -> bool:
        """Check if target is a WordPress site"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{target}/wp-login.php") as response:
                    return response.status == 200
        except:
            return False

    def _parse_ssl_output(self, output: str) -> Dict[str, Any]:
        """Parse OpenSSL output"""
        results = {
            "protocol": None,
            "cipher": None,
            "certificate": {}
        }
        
        # Extract relevant information using regex
        protocol_match = re.search(r"Protocol\s*:\s*(.*)", output)
        if protocol_match:
            results["protocol"] = protocol_match.group(1)
            
        cipher_match = re.search(r"Cipher\s*:\s*(.*)", output)
        if cipher_match:
            results["cipher"] = cipher_match.group(1)
            
        return results

    def _parse_dns_output(self, output: str) -> List[str]:
        """Parse dig command output"""
        return [line.strip() for line in output.split('\n') if line.strip()]

    def _parse_gobuster_output(self, output: str) -> List[Dict[str, str]]:
        """Parse gobuster output"""
        results = []
        for line in output.split('\n'):
            if line.startswith("Found:"):
                path = line.split("Found:")[1].strip()
                results.append({"path": path})
        return results

    def _parse_wpscan_output(self, output: str) -> Dict[str, Any]:
        """Parse WPScan output"""
        results = {
            "version": None,
            "vulnerabilities": [],
            "plugins": [],
            "themes": []
        }
        
        # Parse the output using regex
        version_match = re.search(r"WordPress version (\d+\.\d+\.\d+)", output)
        if version_match:
            results["version"] = version_match.group(1)
            
        # Extract vulnerabilities
        vuln_matches = re.finditer(r"\[!\] Title: (.*?)\n.*?Fixed in: (.*?)\n", output, re.DOTALL)
        for match in vuln_matches:
            results["vulnerabilities"].append({
                "title": match.group(1),
                "fixed_in": match.group(2)
            })
            
        return results

    async def network_analysis(self, target: str) -> Dict[str, Any]:
        """Perform network analysis using scapy"""
        results = {
            "target": target,
            "network_info": {},
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Set the interface for scapy
            conf.iface = self.default_interface
            
            # Perform TCP traceroute with specific interface
            ans, unans = traceroute(target, maxttl=20, timeout=2, iface=self.default_interface, verbose=0)
            if ans:
                results["network_info"]["traceroute"] = self._parse_traceroute(ans)
            
            # Analyze TCP/IP fingerprint
            syn_scan = TCP(dport=80, flags='S')
            ans = sr1(IP(dst=target)/syn_scan, timeout=2, verbose=0, iface=self.default_interface)
            if ans:
                results["network_info"]["tcp_fingerprint"] = self._analyze_tcp_fingerprint(ans)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Network analysis error: {str(e)}")
            return {"error": str(e)}

    def _parse_traceroute(self, ans) -> List[Dict[str, Any]]:
        """Parse traceroute results"""
        hops = []
        for snd, rcv in ans:
            hop = {
                "ttl": snd.ttl,
                "ip": rcv.src,
                "rtt": rcv.time - snd.time
            }
            try:
                hop["hostname"] = socket.gethostbyaddr(rcv.src)[0]
            except:
                hop["hostname"] = None
            hops.append(hop)
        return hops

    def _analyze_tcp_fingerprint(self, packet) -> Dict[str, Any]:
        """Analyze TCP/IP fingerprint"""
        return {
            "ttl": packet.ttl,
            "window_size": packet.window,
            "flags": packet.flags,
            "options": [{"kind": opt.kind, "length": opt.len} for opt in packet.options]
        } 