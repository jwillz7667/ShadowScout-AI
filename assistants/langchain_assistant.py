from .base_assistant import BaseAssistant, ReasoningStep, VisualizationType
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.document_loaders import TextLoader
from typing import Dict, Any, List
import logging
import aiohttp
import json
import os
from bs4 import BeautifulSoup
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime

class LangchainAssistant(BaseAssistant):
    def __init__(self, message_bus):
        super().__init__(message_bus)
        self.llm = None
        self.embeddings = None
        self.session = None
        self.analysis_chain = None
        self.vulnerability_chain = None
        self.current_analysis_id = None
        self.knowledge_graph = nx.DiGraph()

    async def initialize(self):
        """Initialize Langchain components"""
        try:
            init_step = ReasoningStep(
                step_id="langchain_init",
                description="Initializing Langchain components",
                visualization_type=VisualizationType.DEPENDENCY_MAP,
                data=self._get_component_dependencies()
            )
            await self.log_reasoning_step(init_step)

            # Initialize OpenAI components
            self.llm = OpenAI(temperature=0)
            self.embeddings = OpenAIEmbeddings()
            self.session = aiohttp.ClientSession()
            
            # Create analysis chain
            analysis_prompt = PromptTemplate(
                input_variables=["content"],
                template="""
                Analyze the following web content for security implications:
                {content}
                
                Provide a detailed security analysis including:
                1. Potential vulnerabilities
                2. Information disclosure
                3. Security misconfigurations
                4. Risk assessment
                5. Recommendations
                """
            )
            self.analysis_chain = LLMChain(llm=self.llm, prompt=analysis_prompt)
            
            # Create vulnerability chain
            vuln_prompt = PromptTemplate(
                input_variables=["context"],
                template="""
                Based on the following technical context, identify possible security vulnerabilities:
                {context}
                
                For each vulnerability, provide:
                1. Description
                2. Severity level
                3. Potential impact
                4. Mitigation steps
                """
            )
            self.vulnerability_chain = LLMChain(llm=self.llm, prompt=vuln_prompt)

            await self.publish_discovery({
                "component": "langchain_assistant",
                "status": "initialized",
                "capabilities": self._get_ai_capabilities()
            })
            
        except Exception as e:
            error_step = ReasoningStep(
                step_id="langchain_init_error",
                description=f"Initialization error: {str(e)}",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"error": str(e), "state": "failed"}
            )
            await self.log_reasoning_step(error_step)
            raise

    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run AI-powered analysis"""
        try:
            self.current_analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Initial analysis visualization
            analysis_step = ReasoningStep(
                step_id=f"{self.current_analysis_id}_start",
                description="Starting AI analysis",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"target": target, "mode": "initial"}
            )
            await self.log_reasoning_step(analysis_step)

            results = {
                "content_analysis": await self.analyze_content(target),
                "security_assessment": await self.assess_security(target),
                "vulnerability_analysis": await self.analyze_vulnerabilities(target)
            }
            
            if aggressiveness > 3:
                deep_analysis_step = ReasoningStep(
                    step_id=f"{self.current_analysis_id}_deep",
                    description="Performing deep AI analysis",
                    visualization_type=VisualizationType.DECISION_TREE,
                    data={"analysis_type": "deep", "target": target}
                )
                await self.log_reasoning_step(deep_analysis_step)
                
                results.update({
                    "deep_analysis": await self.perform_deep_analysis(target),
                    "attack_vectors": await self.identify_attack_vectors(target)
                })

            # Final analysis visualization
            final_step = ReasoningStep(
                step_id=f"{self.current_analysis_id}_final",
                description="AI analysis complete",
                visualization_type=VisualizationType.NETWORK_MAP,
                data=self._prepare_results_visualization(results)
            )
            await self.log_reasoning_step(final_step)
            
            return results
            
        except Exception as e:
            error_step = ReasoningStep(
                step_id=f"{self.current_analysis_id}_error",
                description=f"Error in AI analysis: {str(e)}",
                visualization_type=VisualizationType.FLOW_DIAGRAM,
                data={"error": str(e), "state": "failed"}
            )
            await self.log_reasoning_step(error_step)
            raise

    async def analyze_content(self, target: str) -> Dict[str, Any]:
        """Analyze website content"""
        content_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_content",
            description="Analyzing website content",
            visualization_type=VisualizationType.NETWORK_MAP,
            data={"target": target, "type": "content_analysis"}
        )
        await self.log_reasoning_step(content_step)

        try:
            async with self.session.get(target) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Extract text content
                text_content = soup.get_text()
                
                # Split text into chunks
                text_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=1000,
                    chunk_overlap=200
                )
                texts = text_splitter.split_text(text_content)
                
                # Create vector store
                vectorstore = FAISS.from_texts(texts, self.embeddings)
                
                # Analyze content
                analysis = await self.analysis_chain.arun(content="\n".join(texts[:3]))
                
                # Extract and share security implications
                implications = await self._extract_security_implications(analysis)
                if implications:
                    await self.publish_discovery({
                        "type": "security_implications",
                        "findings": implications,
                        "priority": 3
                    })
                
                return {
                    "content_summary": analysis,
                    "relevant_sections": len(texts),
                    "security_implications": implications
                }
                
        except Exception as e:
            await self.publish_alert({
                "type": "content_analysis_error",
                "error": str(e),
                "priority": 3
            })
            return {"error": f"Content analysis failed: {str(e)}"}

    async def assess_security(self, target: str) -> Dict[str, Any]:
        """Assess security posture"""
        security_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_security",
            description="Assessing security posture",
            visualization_type=VisualizationType.HEATMAP,
            data={"target": target, "type": "security_assessment"}
        )
        await self.log_reasoning_step(security_step)

        try:
            async with self.session.get(target) as response:
                headers = dict(response.headers)
                cookies = dict(response.cookies)
                
                context = {
                    "headers": headers,
                    "cookies": cookies,
                    "status": response.status,
                    "url": str(response.url)
                }
                
                assessment = await self.vulnerability_chain.arun(
                    context=json.dumps(context, indent=2)
                )
                
                # Extract and share risk factors
                risk_factors = await self._extract_risk_factors(assessment)
                if risk_factors:
                    await self.publish_vulnerability({
                        "type": "risk_factors",
                        "findings": risk_factors,
                        "priority": 4
                    })
                
                return {
                    "assessment": assessment,
                    "risk_factors": risk_factors
                }
                
        except Exception as e:
            await self.publish_alert({
                "type": "security_assessment_error",
                "error": str(e),
                "priority": 4
            })
            return {"error": f"Security assessment failed: {str(e)}"}

    async def analyze_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Analyze potential vulnerabilities"""
        vuln_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_vuln",
            description="Analyzing vulnerabilities",
            visualization_type=VisualizationType.VULNERABILITY_MATRIX,
            data={"target": target, "type": "vulnerability_analysis"}
        )
        await self.log_reasoning_step(vuln_step)

        try:
            async with self.session.get(target) as response:
                html = await response.text()
                
                # Extract various components
                soup = BeautifulSoup(html, 'html.parser')
                forms = soup.find_all('form')
                scripts = soup.find_all('script')
                links = soup.find_all('a')
                
                context = {
                    "forms": len(forms),
                    "scripts": len(scripts),
                    "links": len(links),
                    "content_sample": html[:5000]
                }
                
                analysis = await self.vulnerability_chain.arun(
                    context=json.dumps(context, indent=2)
                )
                
                return {
                    "vulnerability_analysis": analysis,
                    "components": {
                        "forms": len(forms),
                        "scripts": len(scripts),
                        "links": len(links)
                    }
                }
                
        except Exception as e:
            await self.publish_alert({
                "type": "vulnerability_analysis_error",
                "error": str(e),
                "priority": 4
            })
            return {"error": f"Vulnerability analysis failed: {str(e)}"}

    async def perform_deep_analysis(self, target: str) -> Dict[str, Any]:
        """Perform deep AI analysis"""
        deep_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_deep",
            description="Performing deep analysis",
            visualization_type=VisualizationType.DECISION_TREE,
            data={"target": target, "type": "deep_analysis"}
        )
        await self.log_reasoning_step(deep_step)

        try:
            results = {}
            async with self.session.get(target) as response:
                html = await response.text()
                
                # Create document
                doc = TextLoader(html).load()[0]
                
                # Split into chunks
                text_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=500,
                    chunk_overlap=100
                )
                texts = text_splitter.split_text(doc.page_content)
                
                # Create vector store
                vectorstore = FAISS.from_texts(texts, self.embeddings)
                
                # Perform similarity search
                for text in texts[:5]:
                    similar_docs = vectorstore.similarity_search(text, k=2)
                    results[text[:100]] = [doc.page_content[:200] for doc in similar_docs]
                
                # Identify patterns
                patterns = await self._identify_patterns(texts)
                if patterns:
                    await self.publish_discovery({
                        "type": "pattern_discovery",
                        "patterns": patterns,
                        "priority": 3
                    })
                
                return {
                    "deep_analysis": results,
                    "patterns": patterns
                }
                
        except Exception as e:
            await self.publish_alert({
                "type": "deep_analysis_error",
                "error": str(e),
                "priority": 3
            })
            return {"error": f"Deep analysis failed: {str(e)}"}

    async def identify_attack_vectors(self, target: str) -> Dict[str, Any]:
        """Identify potential attack vectors"""
        vector_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_vectors",
            description="Identifying attack vectors",
            visualization_type=VisualizationType.ATTACK_GRAPH,
            data={"target": target, "type": "attack_vectors"}
        )
        await self.log_reasoning_step(vector_step)

        try:
            vectors = []
            async with self.session.get(target) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Analyze input vectors
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    vectors.append({
                        "type": "form",
                        "action": form.get('action'),
                        "method": form.get('method'),
                        "inputs": len(inputs)
                    })
                
                # Analyze JavaScript
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        vectors.append({
                            "type": "script",
                            "src": script.get('src'),
                            "content_length": len(script.string)
                        })
                
                # Assess vector risks
                risk_assessment = await self._assess_vector_risks(vectors)
                if risk_assessment.get("high_risk_vectors"):
                    await self.publish_vulnerability({
                        "type": "high_risk_vectors",
                        "vectors": risk_assessment["high_risk_vectors"],
                        "priority": 5
                    })
                
                return {
                    "attack_vectors": vectors,
                    "risk_assessment": risk_assessment
                }
                
        except Exception as e:
            await self.publish_alert({
                "type": "vector_analysis_error",
                "error": str(e),
                "priority": 4
            })
            return {"error": f"Attack vector identification failed: {str(e)}"}

    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update AI analysis strategy"""
        strategy_step = ReasoningStep(
            step_id=f"{self.current_analysis_id}_strategy",
            description="Updating AI strategy",
            visualization_type=VisualizationType.FLOW_DIAGRAM,
            data=strategy_data
        )
        await self.log_reasoning_step(strategy_step)

    def _get_component_dependencies(self) -> Dict[str, Any]:
        """Get AI component dependencies for visualization"""
        return {
            "nodes": [
                {"id": "llm", "type": "model"},
                {"id": "embeddings", "type": "processor"},
                {"id": "analysis_chain", "type": "analyzer"},
                {"id": "vulnerability_chain", "type": "analyzer"}
            ],
            "edges": [
                {"source": "llm", "target": "analysis_chain"},
                {"source": "llm", "target": "vulnerability_chain"},
                {"source": "embeddings", "target": "analysis_chain"}
            ]
        }

    def _get_ai_capabilities(self) -> List[str]:
        """Get list of AI capabilities"""
        return [
            "Content Analysis",
            "Security Assessment",
            "Vulnerability Analysis",
            "Pattern Recognition",
            "Attack Vector Identification",
            "Risk Assessment"
        ]

    def _prepare_results_visualization(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare results for visualization"""
        return {
            "findings": results,
            "metrics": {
                "analyzed_sections": len(results.get("content_analysis", {}).get("relevant_sections", [])),
                "identified_vulnerabilities": len(results.get("vulnerability_analysis", {}).get("findings", [])),
                "attack_vectors": len(results.get("attack_vectors", {}).get("vectors", []))
            }
        }

    async def _extract_security_implications(self, analysis: str) -> List[Dict[str, str]]:
        """Extract security implications from analysis"""
        implications = []
        
        # Process analysis text to extract security implications
        # Implementation specific to security implication extraction
        
        return implications

    async def _extract_risk_factors(self, assessment: str) -> List[Dict[str, str]]:
        """Extract risk factors from assessment"""
        risk_factors = []
        
        # Process assessment text to extract risk factors
        # Implementation specific to risk factor extraction
        
        return risk_factors

    async def _identify_patterns(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Identify patterns in text chunks"""
        patterns = []
        
        # Process texts to identify patterns
        # Implementation specific to pattern identification
        
        return patterns

    async def _assess_vector_risks(self, vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess risks for identified attack vectors"""
        assessment = {
            "high_risk_vectors": [],
            "medium_risk_vectors": [],
            "low_risk_vectors": []
        }
        
        # Process vectors to assess risks
        # Implementation specific to risk assessment
        
        return assessment