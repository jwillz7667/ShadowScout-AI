import openai
import asyncio

class OpenAIAssistant:
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
        openai.api_key = self.api_key
        print(f"OpenAIAssistant initialized with model: {self.model}")

    async def generate_response(self, prompt: str) -> str:
        try:
            response = await openai.ChatCompletion.acreate(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150,
                n=1,
                stop=None,
                temperature=0.7,
            )
            reply = response.choices[0].message['content'].strip()
            return reply
        except Exception as e:
            print(f"Error generating response: {e}")
            return "" 