from typing import Dict, Any, List, Callable
import asyncio
from dataclasses import dataclass
from datetime import datetime
import logging
from enum import Enum

class MessageType(Enum):
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"
    ATTACK_VECTOR = "attack_vector"
    STRATEGY = "strategy"
    ALERT = "alert"
    INSIGHT = "insight"
    REQUEST = "request"
    RESPONSE = "response"

@dataclass
class Message:
    type: MessageType
    sender: str
    content: Dict[str, Any]
    timestamp: datetime = datetime.now()
    priority: int = 1  # 1 (lowest) to 5 (highest)
    correlation_id: str = None

class MessageBus:
    def __init__(self):
        self.subscribers: Dict[MessageType, List[Callable]] = {
            message_type: [] for message_type in MessageType
        }
        self.all_subscribers: List[Callable] = []  # New: subscribers for all messages
        self.shared_context = SharedContext()
        self.message_history: List[Message] = []
        self.logger = logging.getLogger("MessageBus")

    async def publish(self, message: Message):
        """Publish a message to all subscribers"""
        self.message_history.append(message)
        self.shared_context.update_from_message(message)
        
        # Notify type-specific subscribers
        for subscriber in self.subscribers[message.type]:
            try:
                await subscriber(message)
            except Exception as e:
                self.logger.error(f"Error delivering message to subscriber: {e}")
        
        # Notify subscribers of all messages
        for subscriber in self.all_subscribers:
            try:
                await subscriber(message)
            except Exception as e:
                self.logger.error(f"Error delivering message to all-subscriber: {e}")

    def subscribe(self, message_type: MessageType, callback: Callable):
        """Subscribe to a specific message type"""
        self.subscribers[message_type].append(callback)

    def subscribe_all(self, callback: Callable):
        """Subscribe to all messages"""
        self.all_subscribers.append(callback)

    def unsubscribe_all(self, callback: Callable):
        """Unsubscribe from all messages"""
        if callback in self.all_subscribers:
            self.all_subscribers.remove(callback)

    def get_message_history(self, message_type: MessageType = None) -> List[Message]:
        """Get message history, optionally filtered by type"""
        if message_type:
            return [msg for msg in self.message_history if msg.type == message_type]
        return self.message_history

class SharedContext:
    def __init__(self):
        self.discoveries: Dict[str, Any] = {}
        self.vulnerabilities: Dict[str, Any] = {}
        self.attack_vectors: Dict[str, Any] = {}
        self.strategies: Dict[str, Any] = {}
        self.insights: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def update_from_message(self, message: Message):
        """Update shared context based on message content"""
        async with self._lock:
            if message.type == MessageType.DISCOVERY:
                self.discoveries.update(message.content)
            elif message.type == MessageType.VULNERABILITY:
                self.vulnerabilities.update(message.content)
            elif message.type == MessageType.ATTACK_VECTOR:
                self.attack_vectors.update(message.content)
            elif message.type == MessageType.STRATEGY:
                self.strategies.update(message.content)
            elif message.type == MessageType.INSIGHT:
                self.insights.update(message.content)

    async def get_context(self) -> Dict[str, Any]:
        """Get the complete shared context"""
        async with self._lock:
            return {
                "discoveries": self.discoveries,
                "vulnerabilities": self.vulnerabilities,
                "attack_vectors": self.attack_vectors,
                "strategies": self.strategies,
                "insights": self.insights
            } 