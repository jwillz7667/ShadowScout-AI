from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate, SystemMessagePromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain.chains import LLMChain
from langchain_core.messages import SystemMessage, HumanMessage
import os
from dotenv import load_dotenv
import asyncio
from datetime import datetime
from typing import Dict, Any
import json

class AIConfig:
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        
        # Load OpenAI API key and model name from environment
        self.api_key = os.getenv('OPENAI_API_KEY')
        self.model_name = os.getenv('MODEL_NAME', 'gpt-4')
        
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        # Initialize ChatOpenAI with specific parameters
        self.llm = ChatOpenAI(
            model_name=self.model_name,
            openai_api_key=self.api_key,
            temperature=0.7,
            request_timeout=120,
            max_retries=3,
            model_kwargs={
                "top_p": 1,
                "frequency_penalty": 0,
                "presence_penalty": 0
            }
        )
        
        # Define system prompts for different assistants
        self.prompts = {
            "browser": """You are a Browser Security Assistant specialized in web application security.
                Your task is to analyze web-based vulnerabilities and provide insights on:
                - XSS vulnerabilities
                - CSRF issues
                - Client-side security problems
                - Browser exploitation techniques
                
                Provide output in valid JSON format.""",
                
            "terminal": """You are a Terminal Security Assistant focused on system-level security.
                Your expertise includes:
                - Command injection vulnerabilities
                - System exploitation techniques
                - Privilege escalation
                - Network protocol analysis
                
                Provide output in valid JSON format.""",
                
            "strategist": """You are an Attack Strategist that analyzes security findings and develops attack plans.
                Your responsibilities include:
                - Analyzing vulnerabilities for attack potential
                - Developing multi-stage attack strategies
                - Identifying attack vectors
                - Prioritizing security issues
                
                Provide output in valid JSON format."""
        }
        
        # Initialize JSON output parser
        self.output_parser = JsonOutputParser()
    
    def create_chain(self, assistant_type: str) -> LLMChain:
        """Create a LangChain chain for specific assistant type"""
        if assistant_type not in self.prompts:
            raise ValueError(f"Unknown assistant type: {assistant_type}")
            
        # Create message templates
        system_message_prompt = SystemMessagePromptTemplate.from_template(self.prompts[assistant_type])
        human_message_prompt = HumanMessagePromptTemplate.from_template("{input}")
        
        # Create chat prompt template
        chat_prompt = ChatPromptTemplate.from_messages([
            system_message_prompt,
            human_message_prompt
        ])
        
        # Create and return the chain
        return LLMChain(
            llm=self.llm,
            prompt=chat_prompt,
            verbose=True,
            output_parser=self.output_parser
        )
    
    async def analyze_with_ai(self, prompt: str, assistant_type: str) -> Dict[str, Any]:
        """Perform actual AI analysis with proper error handling and retries"""
        if assistant_type not in self.prompts:
            raise ValueError(f"Unknown assistant type: {assistant_type}")
        
        try:
            chain = self.create_chain(assistant_type)
            response = await chain.ainvoke({"input": prompt})
            
            # Add realistic delay based on prompt length and complexity
            delay = len(prompt) * 0.01 + 2  # Base delay of 2 seconds + additional time for longer prompts
            await asyncio.sleep(delay)
            
            return response
            
        except Exception as e:
            return {
                "error": f"Analysis failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }