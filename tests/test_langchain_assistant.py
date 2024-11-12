import pytest
from assistants.langchain_assistant import LangchainAssistant

@pytest.mark.asyncio
async def test_langchain_assistant():
    assistant = LangchainAssistant()
    response = await assistant.process_text("Hello, world!")
    assert isinstance(response, str)
    assert len(response) > 0 