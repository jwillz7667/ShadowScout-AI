import logging
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from .message_bus import MessageBus, Message, MessageType
import networkx as nx
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime
import json
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VisualizationType(Enum):
    DECISION_TREE = "decision_tree"
    ATTACK_GRAPH = "attack_graph"
    DEPENDENCY_MAP = "dependency_map"
    FLOW_DIAGRAM = "flow_diagram"
    HEATMAP = "heatmap"
    NETWORK_MAP = "network_map"
    VULNERABILITY_MATRIX = "vulnerability_matrix"

@dataclass
class ReasoningStep:
    step_id: str
    description: str
    visualization_type: VisualizationType
    data: Dict[str, Any]
    timestamp: datetime = datetime.now()
    parent_step: str = None
    alternatives: List[Dict[str, Any]] = None

class BaseAssistant(ABC):
    def __init__(self, name: str, message_bus: MessageBus):
        self.name = name
        self.message_bus = message_bus
        self.message_bus.subscribe_all(self.handle_message)
        
    async def send_message(self, msg_type: MessageType, content: dict, priority: int = 1):
        """Send a message to other assistants via the message bus"""
        message = Message(
            type=msg_type,
            sender=self.name,
            content=content,
            priority=priority
        )
        await self.message_bus.publish(message)
    
    @abstractmethod
    async def handle_message(self, message: Message):
        """Handle incoming messages from other assistants"""
        pass

    @abstractmethod
    async def initialize(self):
        """Initialize the assistant"""
        pass

    @abstractmethod
    async def shutdown(self):
        """Cleanup when shutting down"""
        pass

    async def handle_error(self, error: Exception) -> str:
        self.logger.error(f"Error in {self.__class__.__name__}: {str(error)}")
        return f"An error occurred: {str(error)}" 

    async def publish_discovery(self, content: Dict[str, Any], priority: int = 1):
        """Publish a discovery"""
        await self.message_bus.publish(Message(
            type=MessageType.DISCOVERY,
            sender=self.__class__.__name__,
            content=content,
            priority=priority
        ))

    async def publish_vulnerability(self, content: Dict[str, Any], priority: int = 2):
        """Publish a vulnerability finding"""
        await self.message_bus.publish(Message(
            type=MessageType.VULNERABILITY,
            sender=self.__class__.__name__,
            content=content,
            priority=priority
        ))

    async def publish_attack_vector(self, content: Dict[str, Any], priority: int = 2):
        """Publish an attack vector"""
        await self.message_bus.publish(Message(
            type=MessageType.ATTACK_VECTOR,
            sender=self.__class__.__name__,
            content=content,
            priority=priority
        ))

    async def publish_strategy(self, content: Dict[str, Any], priority: int = 3):
        """Publish a strategy update"""
        await self.message_bus.publish(Message(
            type=MessageType.STRATEGY,
            sender=self.__class__.__name__,
            content=content,
            priority=priority
        ))

    async def publish_alert(self, content: Dict[str, Any], priority: int = 3):
        """Publish an alert"""
        await self.message_bus.publish(Message(
            type=MessageType.ALERT,
            sender=self.__class__.__name__,
            content=content,
            priority=priority
        ))

    async def visualize_reasoning(self, step: ReasoningStep) -> str:
        """Create and return a visualization for a reasoning step"""
        plt.figure(figsize=(10, 6))
        
        if step.visualization_type == VisualizationType.DECISION_TREE:
            self._create_decision_tree(step.data)
        elif step.visualization_type == VisualizationType.ATTACK_GRAPH:
            self._create_attack_graph(step.data)
        elif step.visualization_type == VisualizationType.NETWORK_MAP:
            self._create_network_map(step.data)
        # ... other visualization types
        
        # Convert plot to base64 string
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        # Store visualization in history
        self.visualization_history.append({
            'step_id': step.step_id,
            'timestamp': step.timestamp,
            'visualization': image_base64,
            'type': step.visualization_type.value
        })
        
        return image_base64

    async def share_reasoning(self, step: ReasoningStep):
        """Share reasoning step with other assistants"""
        await self.message_bus.publish(Message(
            type=MessageType.INSIGHT,
            sender=self.__class__.__name__,
            content={
                'type': 'reasoning_step',
                'step': {
                    'id': step.step_id,
                    'description': step.description,
                    'visualization_type': step.visualization_type.value,
                    'data': step.data,
                    'timestamp': step.timestamp.isoformat(),
                    'parent_step': step.parent_step,
                    'alternatives': step.alternatives
                }
            },
            priority=3
        ))

    async def request_collaboration(self, task_type: str, data: Dict[str, Any]):
        """Request collaboration from other assistants"""
        await self.message_bus.publish(Message(
            type=MessageType.REQUEST,
            sender=self.__class__.__name__,
            content={
                'type': 'collaboration_request',
                'task_type': task_type,
                'data': data,
                'timestamp': datetime.now().isoformat()
            },
            priority=4
        ))

    async def handle_collaboration_request(self, message: Message):
        """Handle collaboration requests from other assistants"""
        if message.content.get('type') == 'collaboration_request':
            response = await self._process_collaboration_request(message.content)
            await self.message_bus.publish(Message(
                type=MessageType.RESPONSE,
                sender=self.__class__.__name__,
                content={
                    'type': 'collaboration_response',
                    'request_id': message.content.get('request_id'),
                    'response': response
                },
                priority=4
            ))

    async def _process_collaboration_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a collaboration request"""
        # Implementation in specific assistant classes
        pass

    def _create_decision_tree(self, data: Dict[str, Any]):
        """Create decision tree visualization"""
        G = nx.DiGraph()
        
        def add_nodes(node_data, parent=None):
            node_id = node_data.get('id')
            G.add_node(node_id, label=node_data.get('label'))
            if parent:
                G.add_edge(parent, node_id)
            for child in node_data.get('children', []):
                add_nodes(child, node_id)
        
        add_nodes(data)
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', 
                node_size=1500, arrowsize=20)
        labels = nx.get_node_attributes(G, 'label')
        nx.draw_networkx_labels(G, pos, labels)

    def _create_attack_graph(self, data: Dict[str, Any]):
        """Create attack graph visualization"""
        G = nx.DiGraph()
        
        # Add nodes and edges from data
        for node in data.get('nodes', []):
            G.add_node(node['id'], **node.get('attributes', {}))
        
        for edge in data.get('edges', []):
            G.add_edge(edge['source'], edge['target'], **edge.get('attributes', {}))
        
        # Draw the graph
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightred',
                node_size=1500, arrowsize=20)
        
        # Add edge labels if they exist
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(G, pos, edge_labels)

    def _create_network_map(self, data: Dict[str, Any]):
        """Create network map visualization"""
        G = nx.Graph()
        
        # Add nodes for each host/service
        for node in data.get('nodes', []):
            G.add_node(node['id'], **node.get('attributes', {}))
        
        # Add edges for connections
        for edge in data.get('edges', []):
            G.add_edge(edge['source'], edge['target'], **edge.get('attributes', {}))
        
        # Draw the network map
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightgreen',
                node_size=1500)
        
        # Add labels for services/ports
        labels = nx.get_node_attributes(G, 'service')
        nx.draw_networkx_labels(G, pos, labels)

    async def log_reasoning_step(self, step: ReasoningStep):
        """Log a reasoning step with visualization"""
        self.reasoning_steps.append(step)
        
        # Create visualization
        visualization = await self.visualize_reasoning(step)
        
        # Share with other assistants
        await self.share_reasoning(step)
        
        # Log step details
        self.logger.info(f"Reasoning step: {step.description}")
        
        return visualization

    async def find_alternative_approach(self, failed_step: ReasoningStep) -> ReasoningStep:
        """Find alternative approach when current approach fails"""
        # Get context from other assistants
        context = await self.message_bus.shared_context.get_context()
        
        # Create visualization of the problem
        problem_viz = await self.visualize_reasoning(ReasoningStep(
            step_id=f"problem_{failed_step.step_id}",
            description="Problem Analysis",
            visualization_type=VisualizationType.DECISION_TREE,
            data=self._create_problem_analysis(failed_step, context)
        ))
        
        # Request collaboration from other assistants
        await self.request_collaboration('alternative_approach', {
            'failed_step': failed_step,
            'problem_visualization': problem_viz,
            'context': context
        })
        
        # Create new approach based on responses
        new_approach = self._create_alternative_approach(failed_step, context)
        
        return new_approach

    def _create_problem_analysis(self, failed_step: ReasoningStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create problem analysis visualization data"""
        return {
            'id': 'root',
            'label': 'Problem Analysis',
            'children': [
                {
                    'id': 'failure',
                    'label': f'Failed Step: {failed_step.description}',
                    'children': [
                        {'id': 'cause', 'label': 'Potential Causes'},
                        {'id': 'impact', 'label': 'Impact Analysis'},
                        {'id': 'constraints', 'label': 'Constraints'}
                    ]
                }
            ]
        }

    def _create_alternative_approach(self, failed_step: ReasoningStep, context: Dict[str, Any]) -> ReasoningStep:
        """Create alternative approach based on analysis"""
        # Implementation in specific assistant classes
        pass

    @abstractmethod
    async def run(self, target: str, aggressiveness: int = 5, stealth_mode: bool = False) -> Dict[str, Any]:
        """Run the assistant"""
        pass

    @abstractmethod
    async def update_strategy(self, strategy_data: Dict[str, Any]):
        """Update assistant strategy based on new information"""
        pass