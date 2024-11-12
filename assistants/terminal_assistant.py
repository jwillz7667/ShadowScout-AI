from .base_assistant import BaseAssistant
from typing import Dict, Any, List
import asyncio
import subprocess
import platform
import re
import logging
from datetime import datetime

class TerminalAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.os_type = platform.system().lower()
        self.available_tools = []

    async def initialize(self):
        """Initialize terminal capabilities"""
        self.available_tools = await self._check_available_tools()
        
        await self.publish_discovery({
            "component": "terminal_assistant",
            "os_type": self.os_type,
            "available_tools": self.available_tools
        })

    async def close(self):
        """Cleanup resources"""
        pass

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run terminal-based analysis"""
        try:
            results = {}
            
            # Basic network information
            network_info = await self.gather_network_info(target)
            results["network_info"] = network_info
            
            await self.publish_discovery({
                "type": "network_info",
                "findings": network_info
            })

            # System information
            system_info = await self.gather_system_info()
            results["system_info"] = system_info
            
            # Run port scan if aggressive mode
            if aggressiveness > 3 and not stealth_mode:
                port_scan = await self.run_port_scan(target)
                results["port_scan"] = port_scan
                
                if self._has_critical_ports(port_scan):
                    await self.publish_vulnerability({
                        "type": "exposed_services",
                        "findings": port_scan,
                        "severity": "high",
                        "priority": 4
                    })

                # Service detection
                service_info = await self.detect_services(target)
                results["service_detection"] = service_info
                
                await self.publish_discovery({
                    "type": "service_info",
                    "findings": service_info
                })

            return results
            
        except Exception as e:
            await self.publish_alert({
                "type": "error",
                "component": "terminal_assistant",
                "message": str(e),
                "priority": 4
            })
            raise

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update terminal analysis strategy"""
        if "focus_areas" in strategy_data:
            await self._adjust_scan_focus(strategy_data["focus_areas"])

    async def _check_available_tools(self) -> List[str]:
        """Check which tools are available"""
        tools = ['nmap', 'dig', 'whois', 'traceroute', 'netstat']
        available = []
        
        for tool in tools:
            try:
                await self._run_command(f"which {tool}")
                available.append(tool)
                
                await self.publish_discovery({
                    "type": "tool_available",
                    "tool": tool,
                    "priority": 2
                })
            except:
                pass
                
        return available

    async def _run_command(self, command: str) -> str:
        """Run a shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Command failed: {stderr.decode()}")
                
            return stdout.decode()
        except Exception as e:
            await self.publish_alert({
                "type": "command_error",
                "command": command,
                "error": str(e),
                "priority": 3
            })
            raise

    async def gather_network_info(self, target: str) -> Dict[str, Any]:
        """Gather network information"""
        info = {}
        
        try:
            # DNS information
            if 'dig' in self.available_tools:
                info['dns'] = await self._run_command(f"dig +short {target}")
                
                await self.publish_discovery({
                    "type": "dns_info",
                    "target": target,
                    "findings": info['dns']
                })
            
            # Traceroute
            if 'traceroute' in self.available_tools:
                info['route'] = await self._run_command(f"traceroute -n {target}")
                
                await self.publish_discovery({
                    "type": "route_info",
                    "target": target,
                    "findings": info['route']
                })
            
            # Whois information
            if 'whois' in self.available_tools:
                info['whois'] = await self._run_command(f"whois {target}")
                
                await self.publish_discovery({
                    "type": "whois_info",
                    "target": target,
                    "findings": info['whois']
                })
            
        except Exception as e:
            await self.publish_alert({
                "type": "network_info_error",
                "error": str(e),
                "priority": 3
            })
            
        return info

    async def gather_system_info(self) -> Dict[str, Any]:
        """Gather system information"""
        info = {}
        
        try:
            if self.os_type == 'linux':
                info['os'] = await self._run_command("cat /etc/os-release")
                info['kernel'] = await self._run_command("uname -a")
                info['network'] = await self._run_command("ip addr show")
            elif self.os_type == 'darwin':
                info['os'] = await self._run_command("sw_vers")
                info['network'] = await self._run_command("ifconfig")
            elif self.os_type == 'windows':
                info['os'] = await self._run_command("systeminfo")
                info['network'] = await self._run_command("ipconfig /all")
            
            await self.publish_discovery({
                "type": "system_info",
                "findings": info
            })
            
        except Exception as e:
            await self.publish_alert({
                "type": "system_info_error",
                "error": str(e),
                "priority": 3
            })
            
        return info

    async def run_port_scan(self, target: str) -> Dict[str, Any]:
        """Run port scan"""
        if 'nmap' in self.available_tools:
            try:
                result = await self._run_command(f"nmap -sS -sV {target}")
                parsed_result = self._parse_nmap_output(result)
                
                await self.publish_discovery({
                    "type": "port_scan",
                    "target": target,
                    "findings": parsed_result,
                    "priority": 3
                })
                
                return parsed_result
            except Exception as e:
                await self.publish_alert({
                    "type": "port_scan_error",
                    "error": str(e),
                    "priority": 3
                })
                
        return {"error": "nmap not available"}

    async def detect_services(self, target: str) -> Dict[str, Any]:
        """Detect services"""
        if 'nmap' in self.available_tools:
            try:
                result = await self._run_command(f"nmap -sV -sC {target}")
                parsed_result = self._parse_service_detection(result)
                
                # Check for sensitive services
                if self._has_sensitive_services(parsed_result):
                    await self.publish_vulnerability({
                        "type": "sensitive_service",
                        "findings": parsed_result,
                        "severity": "high",
                        "priority": 4
                    })
                
                return parsed_result
            except Exception as e:
                await self.publish_alert({
                    "type": "service_detection_error",
                    "error": str(e),
                    "priority": 3
                })
                
        return {"error": "nmap not available"}

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        ports = {}
        for line in output.splitlines():
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                port = parts[0]
                state = parts[1]
                service = ' '.join(parts[2:])
                ports[port] = {'state': state, 'service': service}
        return ports

    def _parse_service_detection(self, output: str) -> Dict[str, Any]:
        """Parse service detection output"""
        services = {}
        current_port = None
        
        for line in output.splitlines():
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)', line)
            if port_match:
                current_port = port_match.group(1)
                services[current_port] = {
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4)
                }
            elif current_port and '|' in line:
                if 'details' not in services[current_port]:
                    services[current_port]['details'] = []
                services[current_port]['details'].append(line.strip())
        
        return services

    def _has_critical_ports(self, port_scan: Dict[str, Any]) -> bool:
        """Check for critical ports"""
        critical_ports = {'21', '22', '23', '3389', '445', '135', '139'}
        return any(port in critical_ports for port in port_scan.keys())

    def _has_sensitive_services(self, services: Dict[str, Any]) -> bool:
        """Check for sensitive services"""
        sensitive_services = {
            'mysql', 'mssql', 'oracle', 'postgresql',
            'telnet', 'ftp', 'rdp', 'smb'
        }
        return any(
            service['service'].lower() in sensitive_services
            for service in services.values()
        )

    async def _adjust_scan_focus(self, focus_areas: List[str]):
        """Adjust scan focus based on strategy"""
        # Implementation specific to terminal scanning
        pass