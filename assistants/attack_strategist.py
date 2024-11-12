from typing import Dict, Any, List
import logging
import aiohttp
import json
from datetime import datetime
import asyncio
from urllib.parse import urljoin, urlparse
import networkx as nx
from bs4 import BeautifulSoup, Comment
import re
from functools import reduce
from .base_assistant import BaseAssistant, ReasoningStep, VisualizationType

class AttackStrategist(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.session = None
        self.attack_graph = nx.DiGraph()
        self.visited_urls = set()
        self.attack_vectors = []
        self.current_strategy_id = None

    async def initialize(self):
        """Initialize attack strategist"""
        init_step = ReasoningStep(
            step_id="strategy_init",
            description="Initializing attack strategy components",
            visualization_type=VisualizationType.DEPENDENCY_MAP,
            data=self._get_strategy_components()
        )
        await self.log_reasoning_step(init_step)
        
        self.session = aiohttp.ClientSession()
        self.attack_graph.clear()
        self.visited_urls.clear()
        self.attack_vectors = []
        
        await self.publish_discovery({
            "component": "attack_strategist",
            "status": "initialized",
            "capabilities": self._get_strategy_capabilities()
        })

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run attack strategy analysis"""
        try:
            self.current_strategy_id = f"strategy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Initial strategy visualization
            strategy_step = ReasoningStep(
                step_id=f"{self.current_strategy_id}_start",
                description="Developing initial attack strategy",
                visualization_type=VisualizationType.ATTACK_GRAPH,
                data={"target": target, "mode": "initial"}
            )
            await self.log_reasoning_step(strategy_step)

            results = {
                "attack_surface": await self.analyze_attack_surface(target),
                "attack_paths": await self.identify_attack_paths(target),
                "vulnerability_chain": await self.build_vulnerability_chain(target)
            }
            
            # Share initial findings
            await self.publish_discovery({
                "type": "attack_surface",
                "findings": results["attack_surface"],
                "priority": 4
            })
            
            if aggressiveness > 3 and not stealth_mode:
                advanced_step = ReasoningStep(
                    step_id=f"{self.current_strategy_id}_advanced",
                    description="Planning advanced attack strategies",
                    visualization_type=VisualizationType.ATTACK_GRAPH,
                    data={"phase": "advanced", "target": target}
                )
                await self.log_reasoning_step(advanced_step)
                
                results.update({
                    "advanced_vectors": await self.analyze_advanced_vectors(target),
                    "chained_attacks": await self.plan_chained_attacks(target)
                })
                
                # Share advanced strategies
                await self.publish_strategy({
                    "type": "advanced_strategy",
                    "vectors": results["advanced_vectors"],
                    "chains": results["chained_attacks"],
                    "priority": 5
                })

            # Final strategy visualization
            final_step = ReasoningStep(
                step_id=f"{self.current_strategy_id}_final",
                description="Attack strategy complete",
                visualization_type=VisualizationType.VULNERABILITY_MATRIX,
                data=self._prepare_results_visualization(results)
            )
            await self.log_reasoning_step(final_step)
            
            return results
            
        except Exception as e:
            error_step = ReasoningStep(
                step_id=f"{self.current_strategy_id}_error",
                description=f"Error in strategy analysis: {str(e)}",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"error": str(e), "state": "failed"}
            )
            await self.log_reasoning_step(error_step)
            raise

    async def analyze_attack_surface(self, target: str) -> Dict[str, Any]:
        """Analyze the attack surface"""
        surface_step = ReasoningStep(
            step_id=f"{self.current_strategy_id}_surface",
            description="Analyzing attack surface",
            visualization_type=VisualizationType.NETWORK_MAP,
            data={"target": target, "type": "surface_analysis"}
        )
        await self.log_reasoning_step(surface_step)
        
        surface = {
            "entry_points": [],
            "technologies": [],
            "exposed_functionality": []
        }
        
        try:
            async with self.session.get(target) as response:
                # Analyze headers
                headers = response.headers
                server = headers.get('Server')
                if server:
                    surface["technologies"].append({"type": "server", "value": server})
                
                # Analyze response
                text = await response.text()
                
                # Find forms
                forms = self._extract_forms(text)
                surface["entry_points"].extend([{
                    "type": "form",
                    "method": form.get("method", "GET"),
                    "action": form.get("action", "")
                } for form in forms])
                
                # Find API endpoints
                api_endpoints = self._extract_api_endpoints(text)
                surface["entry_points"].extend([{
                    "type": "api",
                    "endpoint": endpoint
                } for endpoint in api_endpoints])
                
                # Analyze exposed functionality
                surface["exposed_functionality"] = await self._analyze_functionality(text)
                
                # Share findings
                if surface["entry_points"]:
                    await self.publish_discovery({
                        "type": "entry_points",
                        "findings": surface["entry_points"],
                        "priority": 4
                    })
                
                return surface
                
        except Exception as e:
            await self.publish_alert({
                "type": "surface_analysis_error",
                "error": str(e),
                "priority": 3
            })
            return {"error": f"Attack surface analysis failed: {str(e)}"}

    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update attack strategy based on new information"""
        strategy_step = ReasoningStep(
            step_id=f"{self.current_strategy_id}_update",
            description="Updating attack strategy",
            visualization_type=VisualizationType.FLOW_DIAGRAM,
            data=strategy_data
        )
        await self.log_reasoning_step(strategy_step)
        
        # Update attack vectors based on new information
        await self._adjust_attack_vectors(strategy_data)

    def _get_strategy_components(self) -> Dict[str, Any]:
        """Get strategy component dependencies for visualization"""
        return {
            "nodes": [
                {"id": "surface_analyzer", "type": "analyzer"},
                {"id": "path_finder", "type": "analyzer"},
                {"id": "chain_builder", "type": "planner"},
                {"id": "risk_assessor", "type": "analyzer"}
            ],
            "edges": [
                {"source": "surface_analyzer", "target": "path_finder"},
                {"source": "path_finder", "target": "chain_builder"},
                {"source": "chain_builder", "target": "risk_assessor"}
            ]
        }

    def _get_strategy_capabilities(self) -> List[str]:
        """Get list of strategy capabilities"""
        return [
            "Attack Surface Analysis",
            "Attack Path Identification",
            "Vulnerability Chain Building",
            "Advanced Vector Analysis",
            "Attack Chain Planning",
            "Risk Assessment"
        ]

    def _prepare_results_visualization(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for visualization"""
        return {
            "findings": results,
            "metrics": {
                "entry_points": len(results.get("attack_surface", {}).get("entry_points", [])),
                "attack_paths": len(results.get("attack_paths", {}).get("paths", [])),
                "vulnerability_chains": len(results.get("vulnerability_chain", {}).get("chain", [])),
                "risk_level": self._calculate_overall_risk(results)
            }
        }

    def _calculate_overall_risk(self, results: Dict[str, Any]) -> str:
        """Calculate overall risk level from results"""
        risk_scores = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        # Count vulnerabilities by severity
        for chain in results.get("vulnerability_chain", {}).get("chain", []):
            severity = chain.get("vulnerability", {}).get("severity", "low").lower()
            if severity in risk_scores:
                risk_scores[severity] += 1
        
        # Determine overall risk
        if risk_scores["critical"] > 0:
            return "critical"
        elif risk_scores["high"] > 2:
            return "high"
        elif risk_scores["medium"] > 5:
            return "medium"
        return "low"

    async def _adjust_attack_vectors(self, strategy_data: Dict[str, Any]):
        """Adjust attack vectors based on strategy"""
        adjustment_step = ReasoningStep(
            step_id=f"{self.current_strategy_id}_adjust",
            description="Adjusting attack vectors",
            visualization_type=VisualizationType.FLOW_DIAGRAM,
            data=strategy_data
        )
        await self.log_reasoning_step(adjustment_step)
        
        # Update attack vectors based on new strategy
        if "focus_areas" in strategy_data:
            self.attack_vectors = [v for v in self.attack_vectors 
                                 if v["type"] in strategy_data["focus_areas"]]
        
        # Share updated vectors
        await self.publish_strategy({
            "type": "vector_adjustment",
            "vectors": self.attack_vectors,
            "priority": 3
        })

    # Helper methods
    def _extract_forms(self, html: str) -> List[Dict[str, str]]:
        """Extract forms from HTML"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get'),
                'inputs': [
                    {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'required': input_field.get('required', False)
                    }
                    for input_field in form.find_all('input')
                ]
            }
            forms.append(form_data)
        return forms

    def _extract_api_endpoints(self, html: str) -> List[str]:
        """Extract API endpoints from HTML"""
        endpoints = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find API endpoints in scripts
        for script in soup.find_all('script'):
            if script.string:
                # Look for common API patterns
                api_patterns = [
                    r'/api/[\w/]+',
                    r'/v\d+/[\w/]+',
                    r'/rest/[\w/]+',
                    r'/graphql/?[\w/]*'
                ]
                for pattern in api_patterns:
                    matches = re.findall(pattern, script.string)
                    endpoints.update(matches)
        
        return list(endpoints)

    async def _analyze_functionality(self, html: str) -> List[Dict[str, Any]]:
        """Analyze exposed functionality"""
        functionality = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Analyze interactive elements
        for element in soup.find_all(['button', 'a', 'input', 'form']):
            func = {
                'type': element.name,
                'id': element.get('id', ''),
                'class': element.get('class', []),
                'onclick': element.get('onclick', ''),
                'href': element.get('href', '') if element.name == 'a' else None
            }
            functionality.append(func)
        
        return functionality

    async def _recursive_path_analysis(self, url: str, depth: int, max_depth: int):
        """Recursively analyze attack paths"""
        if depth >= max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url) as response:
                text = await response.text()
                
                # Extract links and forms
                soup = BeautifulSoup(text, 'html.parser')
                links = [a.get('href') for a in soup.find_all('a', href=True)]
                forms = self._extract_forms(text)
                
                # Add nodes and edges to graph
                for link in links:
                    full_url = urljoin(url, link)
                    if full_url not in self.visited_urls:
                        self.attack_graph.add_edge(url, full_url, type='link')
                
                for form in forms:
                    form_url = urljoin(url, form['action'])
                    self.attack_graph.add_edge(url, form_url, type='form')
                    
                # Recursively analyze linked pages
                tasks = []
                for link in links:
                    full_url = urljoin(url, link)
                    if full_url not in self.visited_urls:
                        tasks.append(self._recursive_path_analysis(full_url, depth + 1, max_depth))
                
                if tasks:
                    await asyncio.gather(*tasks)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing path {url}: {str(e)}")

    def _identify_critical_paths(self) -> List[List[str]]:
        """Identify critical attack paths"""
        critical_paths = []
        
        # Find paths to high-value targets
        high_value_nodes = [
            node for node in self.attack_graph.nodes()
            if any(pattern in node for pattern in [
                'admin', 'login', 'dashboard', 'config',
                'settings', 'user', 'account', 'api'
            ])
        ]
        
        # Get shortest paths to high-value targets
        for target in high_value_nodes:
            paths = nx.shortest_path(self.attack_graph, source=list(self.attack_graph.nodes())[0])
            if target in paths:
                critical_paths.append(paths[target])
        
        return critical_paths

    async def _analyze_vulnerabilities(self, html: str) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities in HTML"""
        vulnerabilities = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check for common security issues
        checks = {
            'xss': self._check_xss_vulnerabilities(soup),
            'csrf': self._check_csrf_vulnerabilities(soup),
            'info_disclosure': self._check_information_disclosure(soup),
            'insecure_configs': self._check_insecure_configurations(soup)
        }
        
        for vuln_type, results in checks.items():
            vulnerabilities.extend(results)
        
        return vulnerabilities

    def _extract_links(self, html: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for a in soup.find_all('a', href=True):
            href = a.get('href')
            if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                links.add(href)
        
        return list(links)

    async def _analyze_auth_vectors(self, html: str) -> List[Dict[str, Any]]:
        """Analyze authentication vectors"""
        vectors = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find login forms
        login_forms = soup.find_all('form', id=lambda x: x and 'login' in x.lower())
        for form in login_forms:
            vectors.append({
                'type': 'login_form',
                'inputs': [input.get('name') for input in form.find_all('input')],
                'action': form.get('action'),
                'method': form.get('method', 'post')
            })
        
        return vectors

    async def _analyze_input_vectors(self, html: str) -> List[Dict[str, Any]]:
        """Analyze input vectors"""
        vectors = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Analyze all input fields
        for input_field in soup.find_all('input'):
            vectors.append({
                'type': input_field.get('type', 'text'),
                'name': input_field.get('name'),
                'validation': {
                    'required': input_field.get('required', False),
                    'pattern': input_field.get('pattern'),
                    'maxlength': input_field.get('maxlength')
                }
            })
        
        return vectors

    async def _analyze_logic_vectors(self, html: str) -> List[Dict[str, Any]]:
        """Analyze logic flow vectors"""
        vectors = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Analyze JavaScript for logic flows
        for script in soup.find_all('script'):
            if script.string:
                vectors.extend(self._analyze_javascript_logic(script.string))
        
        return vectors

    def _calculate_vector_risks(self, vectors: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate risks for attack vectors"""
        risks = {
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vector in vectors:
            risk_level = self._assess_vector_risk(vector)
            risks[risk_level] += 1
        
        return risks

    def _assess_attack_complexity(self, vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess attack complexity"""
        return {
            'complexity_score': len(vectors),
            'required_tools': self._identify_required_tools(vectors),
            'estimated_time': self._estimate_attack_time(vectors),
            'success_probability': self._calculate_success_probability(vectors)
        }

    async def _build_attack_chain(self, entry_point: Dict[str, Any]) -> Dict[str, Any]:
        """Build attack chain from entry point"""
        chain = {
            'entry_point': entry_point,
            'steps': [],
            'requirements': [],
            'estimated_success_rate': 0.0
        }
        
        # Analyze entry point
        if entry_point['type'] == 'form':
            chain['steps'] = await self._analyze_form_attack_steps(entry_point)
        elif entry_point['type'] == 'api':
            chain['steps'] = await self._analyze_api_attack_steps(entry_point)
        
        # Calculate success rate
        chain['estimated_success_rate'] = self._calculate_chain_success_rate(chain)
        
        return chain

    def _analyze_chain_complexity(self, chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack chain complexity"""
        return {
            'total_chains': len(chains),
            'average_steps': sum(len(chain['steps']) for chain in chains) / len(chains) if chains else 0,
            'success_probability': self._calculate_overall_success_probability(chains),
            'complexity_factors': self._identify_complexity_factors(chains)
        }

    # Additional helper methods
    def _check_xss_vulnerabilities(self, soup) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities"""
        vulns = []
        
        # Check for reflected input fields
        for input_field in soup.find_all('input'):
            if input_field.get('type') in ['text', 'search', 'url', 'tel', 'email']:
                vulns.append({
                    'type': 'potential_xss',
                    'location': f"input:{input_field.get('name', '')}",
                    'severity': 'high',
                    'description': 'Unsanitized input field could be vulnerable to XSS'
                })
        
        # Check for unsafe JavaScript practices
        for script in soup.find_all('script'):
            if script.string and any(risk in script.string.lower() for risk in [
                'document.write', 'innerHTML', 'eval(', 'fromCharCode'
            ]):
                vulns.append({
                    'type': 'unsafe_js',
                    'location': 'script',
                    'severity': 'high',
                    'description': 'Potentially unsafe JavaScript practices detected'
                })
        
        return vulns

    def _check_csrf_vulnerabilities(self, soup) -> List[Dict[str, Any]]:
        """Check for CSRF vulnerabilities"""
        vulns = []
        
        # Check forms for CSRF tokens
        for form in soup.find_all('form', method=True):
            if form.get('method').lower() == 'post':
                csrf_token = None
                for input_field in form.find_all('input'):
                    if any(token in input_field.get('name', '').lower() 
                          for token in ['csrf', 'token', '_token']):
                        csrf_token = True
                        break
                
                if not csrf_token:
                    vulns.append({
                        'type': 'csrf',
                        'location': f"form:{form.get('id', '')}",
                        'severity': 'high',
                        'description': 'POST form without CSRF protection'
                    })
        
        return vulns

    def _check_information_disclosure(self, soup) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        vulns = []
        
        # Check for exposed email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, str(soup))
        if emails:
            vulns.append({
                'type': 'info_disclosure',
                'subtype': 'email',
                'severity': 'medium',
                'findings': emails
            })
        
        # Check for exposed internal paths
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            if any(s in comment.lower() for s in ['path', 'root', 'directory', 'internal']):
                vulns.append({
                    'type': 'info_disclosure',
                    'subtype': 'path',
                    'severity': 'medium',
                    'content': comment
                })
        
        return vulns

    def _check_insecure_configurations(self, soup) -> List[Dict[str, Any]]:
        """Check for insecure configurations"""
        vulns = []
        
        # Check for insecure cookie attributes
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('http-equiv', '').lower() == 'set-cookie':
                if 'secure' not in tag.get('content', '').lower():
                    vulns.append({
                        'type': 'insecure_config',
                        'subtype': 'cookie',
                        'severity': 'high',
                        'description': 'Insecure cookie configuration detected'
                    })
        
        # Check for mixed content
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http:'):
                vulns.append({
                    'type': 'insecure_config',
                    'subtype': 'mixed_content',
                    'severity': 'medium',
                    'location': str(tag)
                })
        
        return vulns

    def _analyze_javascript_logic(self, js_code: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript logic flows"""
        flows = []
        
        # Check for sensitive operations
        sensitive_patterns = {
            'authentication': r'(login|auth|password|credential)',
            'data_transfer': r'(ajax|fetch|xhr|axios)',
            'storage': r'(localStorage|sessionStorage|cookie)',
            'dom_manipulation': r'(innerHTML|outerHTML|document\.write)',
            'eval_usage': r'(eval|Function|setTimeout|setInterval)\s*\(',
        }
        
        for flow_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                flows.append({
                    'type': flow_type,
                    'location': match.start(),
                    'context': js_code[max(0, match.start()-50):match.start()+50],
                    'risk_level': 'high' if flow_type in ['eval_usage', 'dom_manipulation'] else 'medium'
                })
        
        return flows

    def _assess_vector_risk(self, vector: Dict[str, Any]) -> str:
        """Assess risk level of a vector"""
        high_risk_types = ['auth_bypass', 'rce', 'sql_injection', 'file_inclusion']
        medium_risk_types = ['xss', 'csrf', 'ssrf', 'info_disclosure']
        
        if vector.get('type') in high_risk_types:
            return 'high'
        elif vector.get('type') in medium_risk_types:
            return 'medium'
        return 'low'

    def _identify_required_tools(self, vectors: List[Dict[str, Any]]) -> List[str]:
        """Identify tools required for exploitation"""
        tools = set()
        
        for vector in vectors:
            if 'sql_injection' in str(vector):
                tools.add('sqlmap')
            if 'xss' in str(vector):
                tools.add('xssstrike')
            if 'port_scan' in str(vector):
                tools.add('nmap')
            if 'brute_force' in str(vector):
                tools.add('hydra')
        
        return list(tools)

    def _estimate_attack_time(self, vectors: List[Dict[str, Any]]) -> int:
        """Estimate time required for attack in minutes"""
        total_time = 0
        
        for vector in vectors:
            # Base time for each vector type
            time_estimates = {
                'brute_force': 120,
                'sql_injection': 60,
                'xss': 30,
                'csrf': 15,
                'info_disclosure': 10
            }
            
            vector_type = vector.get('type', '')
            total_time += time_estimates.get(vector_type, 20)
        
        return total_time

    def _calculate_success_probability(self, vectors: List[Dict[str, Any]]) -> float:
        """Calculate probability of successful attack"""
        if not vectors:
            return 0.0
            
        probabilities = []
        for vector in vectors:
            # Base probabilities for different vector types
            base_probs = {
                'high': 0.8,
                'medium': 0.5,
                'low': 0.3
            }
            
            risk_level = self._assess_vector_risk(vector)
            probabilities.append(base_probs.get(risk_level, 0.2))
        
        # Return average probability
        return sum(probabilities) / len(probabilities)

    def _calculate_chain_success_rate(self, chain: Dict[str, Any]) -> float:
        """Calculate success rate for attack chain"""
        if not chain.get('steps'):
            return 0.0
            
        # Calculate probability of each step succeeding
        step_probabilities = []
        for step in chain['steps']:
            base_prob = 0.9  # Base probability
            
            # Adjust based on step complexity
            complexity = step.get('complexity', 'medium')
            complexity_modifiers = {'low': 1.1, 'medium': 1.0, 'high': 0.7}
            base_prob *= complexity_modifiers.get(complexity, 1.0)
            
            # Adjust based on detection risk
            detection_risk = step.get('detection_risk', 'medium')
            risk_modifiers = {'low': 1.1, 'medium': 1.0, 'high': 0.6}
            base_prob *= risk_modifiers.get(detection_risk, 1.0)
            
            step_probabilities.append(min(base_prob, 1.0))
        
        # Calculate overall probability (all steps must succeed)
        return reduce(lambda x, y: x * y, step_probabilities)

    def _calculate_overall_success_probability(self, chains: List[Dict[str, Any]]) -> float:
        """Calculate overall success probability"""
        if not chains:
            return 0.0
            
        # Calculate success probability for each chain
        chain_probabilities = [
            self._calculate_chain_success_rate(chain)
            for chain in chains
        ]
        
        # Return the probability of at least one chain succeeding
        # P(success) = 1 - P(all chains fail)
        return 1 - reduce(lambda x, y: x * (1 - y), chain_probabilities, 1)

    def _identify_complexity_factors(self, chains: List[Dict[str, Any]]) -> List[str]:
        """Identify factors affecting complexity"""
        factors = set()
        
        for chain in chains:
            # Check for authentication requirements
            if any('auth' in str(step) for step in chain.get('steps', [])):
                factors.add('authentication_required')
                
            # Check for rate limiting
            if any('rate' in str(step) for step in chain.get('steps', [])):
                factors.add('rate_limiting_present')
                
            # Check for WAF presence
            if any('waf' in str(step) for step in chain.get('steps', [])):
                factors.add('waf_detected')
                
            # Check for monitoring systems
            if any('monitor' in str(step) for step in chain.get('steps', [])):
                factors.add('monitoring_systems_present')
        
        return list(factors)