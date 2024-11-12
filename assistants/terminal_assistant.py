import asyncio
from assistants.openai_assistants import OpenAIAssistant
from config.config import Config
import subprocess

class TerminalAssistant:
    def __init__(self):
        self.assistant = OpenAIAssistant(model=Config.MODEL_NAME, api_key=Config.OPENAI_API_KEY)
        self.shell = Config.TERMINAL_SETTINGS.get('shell', '/bin/bash')
        print(f"Initialized TerminalAssistant with shell={self.shell}")

    async def execute_command(self, command: str) -> str:
        prompt = f"Execute the following command in {self.shell}: {command}"
        response = await self.assistant.generate_response(prompt)
        print(f"Terminal Assistant Response: {response}")
        try:
            result = subprocess.run([self.shell, '-c', command], capture_output=True, text=True, check=True)
            print(f"Command Output: {result.stdout}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Error executing command '{command}': {e.stderr}"
            print(error_msg)
            raise Exception(error_msg) 