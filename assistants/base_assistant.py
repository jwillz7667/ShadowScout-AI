import logging
from typing import Optional
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseAssistant(ABC):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def process_request(self, input_text: str) -> str:
        pass
    
    async def handle_error(self, error: Exception) -> str:
        self.logger.error(f"Error in {self.__class__.__name__}: {str(error)}")
        return f"An error occurred: {str(error)}" 