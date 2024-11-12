import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table

@dataclass
class ScanPhase:
    name: str
    status: str
    start_time: float
    end_time: Optional[float] = None
    results: Optional[Dict] = None
    errors: List[str] = None

class Orchestrator:
    def __init__(self, assistants: Dict):
        self.assistants = assistants
        self.scan_phases = []
        self.current_phase = None
        self.scan_context = {}
        self.target_url = None
        self.adaptive_mode = True
        self.console = Console()
        
    async def orchestrate_scan(self, target_url: str) -> Dict:
        """Orchestrate the entire scanning process with detailed progress display."""
        self.target_url = target_url
        scan_results = {}
        
        self.console.print(Panel.fit(
            f"[bold blue]Starting ShadowScout AI Scan[/bold blue]\nTarget: {target_url}",
            border_style="blue"
        ))
        
        try:
            with Progress(
                SpinnerColumn(),
                *Progress.get_default_columns(),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                # Phase 1: Initial Assessment
                task = progress.add_task("[cyan]Initial Assessment", total=100)
                initial_phase = await self._execute_phase(
                    "initial_assessment",
                    self._run_initial_assessment,
                    "Performing initial target assessment",
                    progress,
                    task
                )
                
                # Display initial findings
                self._display_phase_results("Initial Assessment", initial_phase.results)
                
                # Adjust strategy based on initial findings
                await self._adjust_scan_strategy(initial_phase.results)
                
                # Phase 2: Deep Reconnaissance
                task = progress.add_task("[green]Deep Reconnaissance", total=100)
                recon_phase = await self._execute_phase(
                    "reconnaissance",
                    self._run_deep_reconnaissance,
                    "Executing deep reconnaissance",
                    progress,
                    task
                )
                self._display_phase_results("Reconnaissance", recon_phase.results)
                
                # Phase 3: Vulnerability Analysis
                task = progress.add_task("[yellow]Vulnerability Analysis", total=100)
                vuln_phase = await self._execute_phase(
                    "vulnerability_analysis",
                    self._run_vulnerability_analysis,
                    "Analyzing vulnerabilities",
                    progress,
                    task
                )
                self._display_phase_results("Vulnerability Analysis", vuln_phase.results)
                
                # Phase 4: Attack Strategy Development
                task = progress.add_task("[magenta]Attack Strategy Development", total=100)
                strategy_phase = await self._execute_phase(
                    "attack_strategy",
                    self._develop_attack_strategy,
                    "Developing attack strategy",
                    progress,
                    task
                )
                self._display_phase_results("Attack Strategy Development", strategy_phase.results)
                
                # Phase 5: Execution (if findings warrant it)
                if self._should_execute_attacks(strategy_phase.results):
                    task = progress.add_task("[red]Attack Execution", total=100)
                    execution_phase = await self._execute_phase(
                        "attack_execution",
                        self._execute_attacks,
                        "Executing targeted attacks",
                        progress,
                        task
                    )
                    self._display_phase_results("Attack Execution", execution_phase.results)
                    scan_results['execution'] = execution_phase.results
                
                # Final Analysis and Reporting
                task = progress.add_task("[green]Final Analysis", total=100)
                final_phase = await self._execute_phase(
                    "final_analysis",
                    self._generate_final_analysis,
                    "Generating final analysis",
                    progress,
                    task
                )
                self._display_phase_results("Final Analysis", final_phase.results)
                
            return self._compile_final_results()
            
        except Exception as e:
            self.console.print(f"[bold red]Error during scan: {str(e)}[/bold red]")
            await self._handle_orchestration_error(e)
            return {"error": str(e), "partial_results": scan_results}

    def _display_phase_results(self, phase_name: str, results: Dict):
        """Display phase results in a formatted table."""
        self.console.print(f"\n[bold cyan]{phase_name} Results:[/bold cyan]")
        
        if not results:
            self.console.print("[yellow]No results to display[/yellow]")
            return
            
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Category")
        table.add_column("Finding")
        
        for category, finding in self._flatten_results(results).items():
            table.add_row(
                str(category),
                str(finding)[:100] + ("..." if len(str(finding)) > 100 else "")
            )
            
        self.console.print(table)

    def _flatten_results(self, results: Dict, parent_key: str = "") -> Dict:
        """Flatten nested dictionary for display."""
        flattened = {}
        for key, value in results.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            
            if isinstance(value, dict):
                flattened.update(self._flatten_results(value, new_key))
            else:
                flattened[new_key] = value
                
        return flattened

    async def _execute_phase(self, phase_name: str, phase_func, description: str, 
                           progress: Progress, task) -> ScanPhase:
        """Execute a scan phase with detailed progress updates."""
        phase = ScanPhase(
            name=phase_name,
            status="running",
            start_time=asyncio.get_event_loop().time(),
            errors=[]
        )
        self.current_phase = phase
        self.scan_phases.append(phase)
        
        self.console.print(f"\n[bold blue]=== {description} ===[/bold blue]")
        
        try:
            progress.update(task, advance=10)
            phase.results = await phase_func()
            progress.update(task, advance=90)
            phase.status = "completed"
            
            self.console.print(f"[green]✓ {phase_name} completed successfully[/green]")
            
        except Exception as e:
            phase.status = "failed"
            phase.errors.append(str(e))
            self.console.print(f"[red]✗ {phase_name} failed: {str(e)}[/red]")
            
            if self.adaptive_mode:
                self.console.print("[yellow]Attempting recovery...[/yellow]")
                recovery_results = await self._attempt_phase_recovery(phase)
                if recovery_results:
                    phase.results = recovery_results
                    phase.status = "recovered"
                    self.console.print("[green]Recovery successful[/green]")
                    
        finally:
            phase.end_time = asyncio.get_event_loop().time()
            progress.update(task, completed=100)
            
        return phase

    async def _run_initial_assessment(self) -> Dict:
        """Perform initial target assessment."""
        langchain = self.assistants['langchain']
        security = self.assistants['security']
        
        initial_scan = await security.run_passive_scan(self.target_url)
        tech_analysis = await langchain.process_text(
            f"Analyze {self.target_url} for technology stack and potential security implications."
        )
        
        return {
            "passive_scan": initial_scan,
            "tech_analysis": tech_analysis
        }

    async def _run_deep_reconnaissance(self) -> Dict:
        """Execute deep reconnaissance based on initial findings."""
        browser = self.assistants['browser']
        security = self.assistants['security']
        
        tasks = [
            security._discover_endpoints(self.target_url),
            security._enumerate_subdomains(self.target_url),
            browser.check_robots(self.target_url)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            "endpoints": results[0],
            "subdomains": results[1],
            "robots_sitemap": results[2]
        }

    async def _run_vulnerability_analysis(self) -> Dict:
        """Analyze target for vulnerabilities."""
        attack_strategist = self.assistants['attack_strategist']
        security = self.assistants['security']
        
        scan_results = await security.get_scan_summary()
        attack_recommendations = await attack_strategist.analyze_scan_results(scan_results)
        
        return {
            "scan_summary": scan_results,
            "attack_recommendations": attack_recommendations
        }

    async def _develop_attack_strategy(self) -> Dict:
        """Develop comprehensive attack strategy."""
        attack_strategist = self.assistants['attack_strategist']
        offensive = self.assistants['offensive']
        
        strategy = await attack_strategist.get_attack_recommendations()
        attack_plan = await offensive.plan_attack(strategy)
        
        return {
            "strategy": strategy,
            "attack_plan": attack_plan
        }

    async def _execute_attacks(self) -> Dict:
        """Execute planned attacks."""
        offensive = self.assistants['offensive']
        strategy = self.current_phase.results['strategy']
        
        return await offensive.execute_attack_plan(self.target_url, strategy)

    async def _generate_final_analysis(self) -> Dict:
        """Generate final analysis and recommendations."""
        langchain = self.assistants['langchain']
        
        all_results = self._compile_phase_results()
        final_analysis = await langchain.process_text(
            f"Generate comprehensive security analysis for {self.target_url} "
            f"based on the following results: {json.dumps(all_results)}"
        )
        
        return {
            "final_analysis": final_analysis,
            "scan_summary": all_results
        }

    async def _adjust_scan_strategy(self, initial_results: Dict):
        """Adjust scanning strategy based on initial findings."""
        if "error" in str(initial_results).lower():
            self.adaptive_mode = True
            print("\nSwitching to adaptive scanning mode due to initial resistance")
        
        if "wordpress" in str(initial_results).lower():
            print("\nDetected WordPress - adjusting scan strategy for CMS focus")
            
        if "firewall" in str(initial_results).lower():
            print("\nDetected WAF - adjusting scan patterns for evasion")

    def _should_execute_attacks(self, strategy_results: Dict) -> bool:
        """Determine if attack execution is warranted."""
        if not strategy_results:
            return False
            
        high_risk_vectors = [
            vec for vec in strategy_results.get('vectors', [])
            if vec.get('severity') == 'High'
        ]
        
        return len(high_risk_vectors) > 0

    async def _attempt_phase_recovery(self, failed_phase: ScanPhase) -> Optional[Dict]:
        """Attempt to recover from phase failure."""
        print(f"\nAttempting recovery for failed phase: {failed_phase.name}")
        
        try:
            if failed_phase.name == "initial_assessment":
                return await self._run_alternative_assessment()
            elif failed_phase.name == "reconnaissance":
                return await self._run_limited_recon()
            elif failed_phase.name == "vulnerability_analysis":
                return await self._run_passive_vuln_scan()
                
            return None
        except Exception as e:
            print(f"Recovery attempt failed: {str(e)}")
            return None

    def _compile_final_results(self) -> Dict:
        """Compile and display final results."""
        results = {
            "target_url": self.target_url,
            "scan_duration": self._calculate_scan_duration(),
            "phases": [
                {
                    "name": phase.name,
                    "status": phase.status,
                    "duration": phase.end_time - phase.start_time if phase.end_time else None,
                    "results": phase.results,
                    "errors": phase.errors
                }
                for phase in self.scan_phases
            ],
            "final_analysis": self.scan_phases[-1].results if self.scan_phases else None
        }
        
        # Display final summary
        self.console.print("\n[bold green]Scan Complete[/bold green]")
        self.console.print(Panel.fit(
            f"Total Duration: {self._calculate_scan_duration():.2f} seconds\n"
            f"Phases Completed: {len([p for p in self.scan_phases if p.status == 'completed'])}\n"
            f"Phases Failed: {len([p for p in self.scan_phases if p.status == 'failed'])}\n"
            f"Phases Recovered: {len([p for p in self.scan_phases if p.status == 'recovered'])}",
            title="[bold]Scan Summary[/bold]",
            border_style="green"
        ))
        
        return results

    def _calculate_scan_duration(self) -> float:
        """Calculate total scan duration."""
        if not self.scan_phases:
            return 0
        return self.scan_phases[-1].end_time - self.scan_phases[0].start_time 

    def _compile_phase_results(self) -> Dict:
        """Compile results from all phases."""
        return {
            phase.name: {
                "status": phase.status,
                "duration": phase.end_time - phase.start_time if phase.end_time else None,
                "results": phase.results,
                "errors": phase.errors
            }
            for phase in self.scan_phases
        }

    async def _run_alternative_assessment(self) -> Dict:
        """Run alternative assessment when primary fails."""
        browser = self.assistants['browser']
        security = self.assistants['security']
        
        try:
            content = await browser.browse_page(self.target_url)
            headers = await security.analyze_headers(self.target_url)
            return {
                "content_analysis": content,
                "headers_analysis": headers
            }
        except Exception as e:
            return {"error": f"Alternative assessment failed: {str(e)}"}

    async def _run_limited_recon(self) -> Dict:
        """Run limited reconnaissance when full recon fails."""
        security = self.assistants['security']
        try:
            return {
                "headers": await security.analyze_headers(self.target_url),
                "endpoints": await security._discover_endpoints(self.target_url)
            }
        except Exception as e:
            return {"error": f"Limited recon failed: {str(e)}"}

    async def _run_passive_vuln_scan(self) -> Dict:
        """Run passive vulnerability scan when active scan fails."""
        security = self.assistants['security']
        try:
            return await security.run_passive_scan(self.target_url)
        except Exception as e:
            return {"error": f"Passive vulnerability scan failed: {str(e)}"}