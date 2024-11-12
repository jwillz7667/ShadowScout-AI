from typing import Dict, Any, List, Set
from .browser_assistant import BrowserAssistant
from .terminal_assistant import TerminalAssistant
from .langchain_assistant import LangchainAssistant
from .security_tools import SecurityTools
from .attack_strategist import AttackStrategist
from .offensive_tools import OffensiveTools
from .message_bus import MessageBus, Message, MessageType
import logging
import asyncio
from datetime import datetime
import uuid

class Orchestrator:
    def __init__(self):
        self.logger = logging.getLogger("Orchestrator")
        self.message_bus = MessageBus()
        
        # Initialize assistants
        self.browser = BrowserAssistant(self.message_bus)
        self.terminal = TerminalAssistant(self.message_bus)
        self.langchain = LangchainAssistant(self.message_bus)
        self.security = SecurityTools(self.message_bus)
        self.attack_strategist = AttackStrategist(self.message_bus)
        self.offensive_tools = OffensiveTools(self.message_bus)
        
        # Set up message handlers
        self._setup_message_handlers()

    def _setup_message_handlers(self):
        """Set up handlers for different message types"""
        self.message_bus.subscribe(
            MessageType.DISCOVERY,
            self._handle_discovery
        )
        self.message_bus.subscribe(
            MessageType.VULNERABILITY,
            self._handle_vulnerability
        )
        self.message_bus.subscribe(
            MessageType.ATTACK_VECTOR,
            self._handle_attack_vector
        )
        self.message_bus.subscribe(
            MessageType.STRATEGY,
            self._handle_strategy
        )
        self.message_bus.subscribe(
            MessageType.ALERT,
            self._handle_alert
        )

    async def _handle_discovery(self, message: Message):
        """Handle discovery messages"""
        if message.priority >= 4:  # High priority discovery
            # Notify all assistants immediately
            await self._broadcast_insight(message.content)
        
        # Update scan strategy based on discovery
        await self.attack_strategist.update_strategy(message.content)

    async def _handle_vulnerability(self, message: Message):
        """Handle vulnerability messages"""
        # Correlate with existing discoveries
        context = await self.message_bus.shared_context.get_context()
        
        if self._is_critical_vulnerability(message.content):
            # Adjust scan priorities
            await self._adjust_scan_priorities(message.content)
            
            # Notify security tools for immediate analysis
            await self.security.analyze_vulnerability(message.content)

    async def _handle_attack_vector(self, message: Message):
        """Handle attack vector messages"""
        # Update attack strategy
        await self.attack_strategist.incorporate_vector(message.content)
        
        # Check if vector requires specific tools
        if required_tools := self._get_required_tools(message.content):
            await self._ensure_tools_available(required_tools)

    async def _handle_strategy(self, message: Message):
        """Handle strategy messages"""
        # Distribute strategy updates to relevant assistants
        for assistant in self._get_relevant_assistants(message.content):
            await assistant.update_strategy(message.content)

    async def _handle_alert(self, message: Message):
        """Handle alert messages"""
        if message.priority >= 4:
            await self._handle_high_priority_alert(message)
        else:
            await self._log_alert(message)

    async def initialize(self):
        """Initialize all assistants"""
        init_tasks = [
            self.browser.initialize(),
            self.terminal.initialize(),
            self.langchain.initialize(),
            self.security.initialize(),
            self.attack_strategist.initialize(),
            self.offensive_tools.initialize()
        ]
        await asyncio.gather(*init_tasks)

    async def close(self):
        """Cleanup all assistants"""
        close_tasks = [
            self.browser.close(),
            self.terminal.close(),
            self.langchain.close(),
            self.security.close(),
            self.attack_strategist.close(),
            self.offensive_tools.close()
        ]
        await asyncio.gather(*close_tasks)

    async def run_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a complete scan with all enabled assistants"""
        results = {}
        
        try:
            await self.initialize()
            
            # Create initial scan context
            scan_context = {
                "target": target,
                "config": config,
                "start_time": datetime.now().isoformat()
            }
            
            # Publish scan start message
            await self.message_bus.publish(Message(
                type=MessageType.STRATEGY,
                sender="orchestrator",
                content=scan_context,
                priority=5
            ))
            
            # Run enabled assistants based on configuration
            scan_tasks = []
            for assistant_name, settings in config.items():
                if settings.get('enabled', False):
                    assistant = getattr(self, assistant_name.lower().replace(' ', '_'))
                    if assistant:
                        scan_tasks.append(assistant.run(
                            target,
                            aggressiveness=settings.get('aggressiveness', 5),
                            stealth_mode=settings.get('stealth_mode', False)
                        ))
            
            # Run all scans concurrently
            assistant_results = await asyncio.gather(*scan_tasks)
            
            # Combine results
            for name, result in zip(config.keys(), assistant_results):
                results[name] = result
            
            # Get insights from shared context
            context = await self.message_bus.shared_context.get_context()
            results['insights'] = context['insights']
            
        finally:
            await self.close()
            
        return results

    def _is_critical_vulnerability(self, vuln_data: Dict[str, Any]) -> bool:
        """Determine if a vulnerability is critical"""
        critical_types = {'rce', 'sql_injection', 'auth_bypass', 'code_execution'}
        return (
            vuln_data.get('severity', '').lower() == 'critical' or
            vuln_data.get('type', '').lower() in critical_types
        )

    async def _adjust_scan_priorities(self, vuln_data: Dict[str, Any]):
        """Adjust scan priorities based on findings"""
        try:
            # Get current context
            context = await self.message_bus.shared_context.get_context()
            
            # Determine which areas need increased focus
            focus_areas = []
            if vuln_data.get('type') in ['sql_injection', 'xss']:
                focus_areas.append('input_validation')
            elif vuln_data.get('type') in ['auth_bypass', 'session_hijacking']:
                focus_areas.append('authentication')
            elif vuln_data.get('type') in ['rce', 'code_execution']:
                focus_areas.append('system_security')
            
            # Create new strategy
            new_strategy = {
                "focus_areas": focus_areas,
                "priority_level": "high",
                "timestamp": datetime.now().isoformat()
            }
            
            # Publish strategy update
            await self.message_bus.publish(Message(
                type=MessageType.STRATEGY,
                sender="orchestrator",
                content=new_strategy,
                priority=5
            ))
            
        except Exception as e:
            self.logger.error(f"Error adjusting scan priorities: {e}")

    def _get_required_tools(self, vector_data: Dict[str, Any]) -> List[str]:
        """Get required tools for an attack vector"""
        required_tools = set()
        
        # Map attack vectors to required tools
        vector_tool_map = {
            'sql_injection': ['sqlmap', 'dbms_scanner'],
            'xss': ['xssstrike', 'xss_scanner'],
            'port_scan': ['nmap', 'masscan'],
            'brute_force': ['hydra', 'medusa'],
            'web_crawl': ['crawler', 'spider'],
            'ssl_scan': ['sslscan', 'testssl'],
            'dns_enum': ['dnsenum', 'dnsrecon']
        }
        
        vector_type = vector_data.get('type', '').lower()
        if vector_type in vector_tool_map:
            required_tools.update(vector_tool_map[vector_type])
            
        return list(required_tools)

    async def _ensure_tools_available(self, required_tools: List[str]):
        """Ensure required tools are available"""
        try:
            # Check tool availability through terminal assistant
            available_tools = await self.terminal.check_tools(required_tools)
            
            missing_tools = set(required_tools) - set(available_tools)
            if missing_tools:
                await self.message_bus.publish(Message(
                    type=MessageType.ALERT,
                    sender="orchestrator",
                    content={
                        "type": "missing_tools",
                        "tools": list(missing_tools),
                        "impact": "Some attack vectors may be unavailable"
                    },
                    priority=4
                ))
                
                # Try to find alternative tools
                alternatives = await self._find_tool_alternatives(missing_tools)
                if alternatives:
                    await self.message_bus.publish(Message(
                        type=MessageType.DISCOVERY,
                        sender="orchestrator",
                        content={
                            "type": "tool_alternatives",
                            "alternatives": alternatives
                        },
                        priority=3
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error ensuring tool availability: {e}")

    def _get_relevant_assistants(self, strategy_data: Dict[str, Any]) -> List[Any]:
        """Get assistants relevant to a strategy"""
        relevant_assistants = []
        
        # Map focus areas to relevant assistants
        focus_assistant_map = {
            'web_security': [self.browser, self.security],
            'network_security': [self.terminal, self.security],
            'authentication': [self.browser, self.security, self.offensive_tools],
            'input_validation': [self.browser, self.offensive_tools],
            'api_security': [self.security, self.offensive_tools],
            'system_security': [self.terminal, self.security],
            'intelligence': [self.langchain, self.attack_strategist]
        }
        
        # Get relevant assistants based on focus areas
        for focus_area in strategy_data.get('focus_areas', []):
            if focus_area in focus_assistant_map:
                relevant_assistants.extend(focus_assistant_map[focus_area])
                
        # Remove duplicates while preserving order
        return list(dict.fromkeys(relevant_assistants))

    async def _handle_high_priority_alert(self, message: Message):
        """Handle high priority alerts"""
        try:
            # Log the alert
            self.logger.warning(f"High priority alert: {message.content}")
            
            # Notify all assistants
            alert_notification = {
                "type": "high_priority_alert",
                "content": message.content,
                "timestamp": datetime.now().isoformat()
            }
            
            # Publish to all assistants
            await self.message_bus.publish(Message(
                type=MessageType.ALERT,
                sender="orchestrator",
                content=alert_notification,
                priority=5
            ))
            
            # Take immediate action based on alert type
            if message.content.get('type') == 'critical_vulnerability':
                await self._handle_critical_vulnerability(message.content)
            elif message.content.get('type') == 'attack_detected':
                await self._handle_active_attack(message.content)
            elif message.content.get('type') == 'system_compromise':
                await self._handle_system_compromise(message.content)
                
        except Exception as e:
            self.logger.error(f"Error handling high priority alert: {e}")

    async def _log_alert(self, message: Message):
        """Log non-critical alerts"""
        try:
            # Format alert for logging
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "type": message.content.get('type', 'unknown'),
                "details": message.content,
                "sender": message.sender
            }
            
            # Add to shared context
            await self.message_bus.shared_context.update_from_message(Message(
                type=MessageType.ALERT,
                sender="orchestrator",
                content=alert_data,
                priority=message.priority
            ))
            
            # Log the alert
            self.logger.info(f"Alert from {message.sender}: {message.content}")
            
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}")

    async def _broadcast_insight(self, insight: Dict[str, Any]):
        """Broadcast insights to all assistants"""
        try:
            # Enrich insight with context
            context = await self.message_bus.shared_context.get_context()
            enriched_insight = {
                "original_insight": insight,
                "related_findings": self._find_related_findings(insight, context),
                "timestamp": datetime.now().isoformat(),
                "correlation_id": str(uuid.uuid4())
            }
            
            # Broadcast to all assistants
            await self.message_bus.publish(Message(
                type=MessageType.INSIGHT,
                sender="orchestrator",
                content=enriched_insight,
                priority=4
            ))
            
            # Update attack strategy if needed
            if self._should_update_strategy(enriched_insight):
                await self._update_attack_strategy(enriched_insight)
                
        except Exception as e:
            self.logger.error(f"Error broadcasting insight: {e}")

    # Additional helper methods
    async def _handle_critical_vulnerability(self, vuln_data: Dict[str, Any]):
        """Handle critical vulnerability detection"""
        try:
            # Pause ongoing scans if necessary
            if vuln_data.get('severity') == 'critical':
                await self._pause_active_scans()

            # Create immediate response plan
            response_plan = {
                "type": "vulnerability_response",
                "vulnerability": vuln_data,
                "immediate_actions": [
                    "pause_scanning",
                    "isolate_affected_components",
                    "gather_evidence"
                ],
                "timestamp": datetime.now().isoformat()
            }

            # Notify all assistants about critical vulnerability
            await self.message_bus.publish(Message(
                type=MessageType.ALERT,
                sender="orchestrator",
                content=response_plan,
                priority=5
            ))

            # Gather additional evidence
            evidence = await self._gather_vulnerability_evidence(vuln_data)
            
            # Update attack strategy
            await self.attack_strategist.update_strategy({
                "type": "critical_vulnerability",
                "evidence": evidence,
                "priority": "immediate"
            })

        except Exception as e:
            self.logger.error(f"Error handling critical vulnerability: {e}")

    async def _handle_active_attack(self, attack_data: Dict[str, Any]):
        """Handle active attack detection"""
        try:
            # Create attack response plan
            response_plan = {
                "type": "attack_response",
                "attack_details": attack_data,
                "actions": [
                    "monitor_attack_path",
                    "collect_indicators",
                    "analyze_attack_pattern"
                ],
                "timestamp": datetime.now().isoformat()
            }

            # Alert all assistants
            await self.message_bus.publish(Message(
                type=MessageType.ALERT,
                sender="orchestrator",
                content=response_plan,
                priority=5
            ))

            # Collect attack indicators
            indicators = await self._collect_attack_indicators(attack_data)

            # Update shared context with attack information
            await self.message_bus.shared_context.update_from_message(Message(
                type=MessageType.INSIGHT,
                sender="orchestrator",
                content={
                    "type": "attack_indicators",
                    "indicators": indicators,
                    "attack_data": attack_data
                },
                priority=5
            ))

        except Exception as e:
            self.logger.error(f"Error handling active attack: {e}")

    async def _handle_system_compromise(self, compromise_data: Dict[str, Any]):
        """Handle system compromise detection"""
        try:
            # Create compromise response plan
            response_plan = {
                "type": "compromise_response",
                "compromise_details": compromise_data,
                "immediate_actions": [
                    "isolate_system",
                    "collect_forensics",
                    "identify_attack_vector"
                ],
                "timestamp": datetime.now().isoformat()
            }

            # Alert all assistants with highest priority
            await self.message_bus.publish(Message(
                type=MessageType.ALERT,
                sender="orchestrator",
                content=response_plan,
                priority=5
            ))

            # Collect forensic data
            forensics = await self._collect_forensic_data(compromise_data)

            # Update attack strategy with compromise information
            await self.attack_strategist.update_strategy({
                "type": "system_compromise",
                "forensics": forensics,
                "priority": "critical"
            })

        except Exception as e:
            self.logger.error(f"Error handling system compromise: {e}")

    async def _find_tool_alternatives(self, missing_tools: Set[str]) -> Dict[str, List[str]]:
        """Find alternative tools for missing ones"""
        tool_alternatives = {
            'nmap': ['masscan', 'unicornscan', 'zmap'],
            'sqlmap': ['sqlninja', 'havij', 'bbqsql'],
            'hydra': ['medusa', 'patator', 'crowbar'],
            'nikto': ['wapiti', 'arachni', 'w3af'],
            'metasploit': ['empire', 'cobalt strike', 'core impact'],
            'burpsuite': ['zap', 'acunetix', 'skipfish'],
            'wireshark': ['tcpdump', 'tshark', 'netsniff-ng']
        }

        alternatives = {}
        for tool in missing_tools:
            if tool in tool_alternatives:
                alternatives[tool] = tool_alternatives[tool]
            else:
                alternatives[tool] = []

        return alternatives

    def _find_related_findings(self, insight: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find findings related to an insight"""
        related_findings = []
        
        # Extract key information from insight
        insight_type = insight.get('type', '')
        insight_content = str(insight.get('content', ''))
        
        # Search through existing findings in context
        for finding_type in ['vulnerabilities', 'discoveries', 'attack_vectors']:
            for finding in context.get(finding_type, []):
                # Check for related content
                if self._is_finding_related(finding, insight_type, insight_content):
                    related_findings.append({
                        'type': finding_type,
                        'finding': finding,
                        "correlation_score": self._calculate_correlation_score(finding, insight)
                    })
        
        # Sort by correlation score
        related_findings.sort(key=lambda x: x['correlation_score'], reverse=True)
        
        return related_findings[:5]  # Return top 5 related findings

    def _should_update_strategy(self, insight: Dict[str, Any]) -> bool:
        """Determine if strategy update is needed"""
        # Conditions that require strategy update
        update_triggers = {
            'new_vulnerability': lambda x: x.get('type') == 'vulnerability' and x.get('severity') in ['high', 'critical'],
            'attack_pattern': lambda x: x.get('type') == 'attack_pattern' and len(x.get('indicators', [])) > 2,
            'critical_discovery': lambda x: x.get('type') == 'discovery' and x.get('priority', 0) >= 4,
            'tool_failure': lambda x: x.get('type') == 'error' and 'tool' in x.get('details', ''),
            'defense_detection': lambda x: x.get('type') == 'detection' and x.get('confidence', 0) > 0.7
        }

        return any(trigger(insight) for trigger in update_triggers.values())

    async def _update_attack_strategy(self, insight: Dict[str, Any]):
        """Update attack strategy based on insight"""
        try:
            # Get current context
            context = await self.message_bus.shared_context.get_context()
            
            # Create strategy update
            strategy_update = {
                "type": "strategy_update",
                "trigger": insight,
                "adjustments": {
                    "priority_areas": self._determine_priority_areas(insight, context),
                    "tool_adjustments": self._determine_tool_adjustments(insight),
                    "scan_intensity": self._calculate_scan_intensity(insight)
                },
                "timestamp": datetime.now().isoformat()
            }

            # Publish strategy update
            await self.message_bus.publish(Message(
                type=MessageType.STRATEGY,
                sender="orchestrator",
                content=strategy_update,
                priority=4
            ))

        except Exception as e:
            self.logger.error(f"Error updating attack strategy: {e}")

    # Additional utility methods
    async def _pause_active_scans(self):
        """Pause all active scanning operations"""
        try:
            await self.message_bus.publish(Message(
                type=MessageType.STRATEGY,
                sender="orchestrator",
                content={"action": "pause_scan", "reason": "critical_vulnerability"},
                priority=5
            ))
        except Exception as e:
            self.logger.error(f"Error pausing scans: {e}")

    async def _gather_vulnerability_evidence(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather additional evidence about a vulnerability"""
        evidence = {
            "timestamp": datetime.now().isoformat(),
            "vulnerability": vuln_data,
            "related_findings": [],
            "system_state": {}
        }
        # Implementation specific to vulnerability evidence gathering
        return evidence

    async def _collect_attack_indicators(self, attack_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect indicators of attack"""
        indicators = []
        # Implementation specific to attack indicator collection
        return indicators

    async def _collect_forensic_data(self, compromise_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect forensic data about system compromise"""
        forensics = {
            "timestamp": datetime.now().isoformat(),
            "compromise_data": compromise_data,
            "system_state": {},
            "affected_components": []
        }
        # Implementation specific to forensic data collection
        return forensics

    def _is_finding_related(self, finding: Dict[str, Any], insight_type: str, insight_content: str) -> bool:
        """Check if a finding is related to an insight"""
        finding_content = str(finding.get('content', ''))
        finding_type = finding.get('type', '')
        
        # Check for type relationship
        type_related = insight_type.lower() in finding_type.lower() or finding_type.lower() in insight_type.lower()
        
        # Check for content similarity
        content_related = any(word in finding_content.lower() for word in insight_content.lower().split())
        
        return type_related or content_related

    def _calculate_correlation_score(self, finding: Dict[str, Any], insight: Dict[str, Any]) -> float:
        """Calculate correlation score between finding and insight"""
        score = 0.0
        
        # Type matching
        if finding.get('type') == insight.get('type'):
            score += 0.5
            
        # Severity matching
        if finding.get('severity') == insight.get('severity'):
            score += 0.3
            
        # Content similarity
        finding_content = str(finding.get('content', ''))
        insight_content = str(insight.get('content', ''))
        common_words = set(finding_content.lower().split()) & set(insight_content.lower().split())
        score += len(common_words) * 0.1
        
        return min(score, 1.0)

    def _determine_priority_areas(self, insight: Dict[str, Any], context: Dict[str, Any]) -> List[str]:
        """Determine priority areas based on insight and context"""
        priority_areas = set()
        
        if insight.get('type') == 'vulnerability':
            priority_areas.add('security')
        if insight.get('type') == 'attack_pattern':
            priority_areas.add('defense')
        if insight.get('type') == 'discovery':
            priority_areas.add('reconnaissance')
            
        return list(priority_areas)

    def _determine_tool_adjustments(self, insight: Dict[str, Any]) -> Dict[str, Any]:
        """Determine tool adjustments based on insight"""
        adjustments = {
            "increase_intensity": [],
            "decrease_intensity": [],
            "disable": [],
            "enable": []
        }
        # Implementation specific to tool adjustments
        return adjustments

    def _calculate_scan_intensity(self, insight: Dict[str, Any]) -> int:
        """Calculate new scan intensity based on insight"""
        base_intensity = 5
        
        # Adjust based on insight type
        type_modifiers = {
            'vulnerability': 2,
            'attack_pattern': 1,
            'discovery': 0,
            'error': -1
        }
        
        # Adjust based on severity
        severity_modifiers = {
            'critical': 3,
            'high': 2,
            'medium': 1,
            'low': 0
        }
        
        intensity = base_intensity
        intensity += type_modifiers.get(insight.get('type', ''), 0)
        intensity += severity_modifiers.get(insight.get('severity', ''), 0)
        
        return max(1, min(intensity, 10))  # Ensure intensity is between 1 and 10