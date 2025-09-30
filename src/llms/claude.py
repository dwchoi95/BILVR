import time
import anthropic
from anthropic.types import ToolUseBlock

class CLAUDE:
    def __init__(self,
                 model:str="claude-opus-4-1",
                 temperature:float=0.0):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
        
        self.client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        self.async_client = anthropic.AsyncAnthropic(api_key=CLAUDE_API_KEY)
        self.model = model
        self.temperature = temperature
        self._tool_name = "structured_output"
        self._schema = {
            "type": "object",
            "properties": {
                "fixed": {"type": "string"}
            },
            "required": ["fixed"],
            "additionalProperties": False
        }
    
    def _extract_fixed(self, response):
        for block in response.content:
            if isinstance(block, ToolUseBlock) and block.name == self._tool_name:
                payload = block.input
                if isinstance(payload, dict) and "fixed" in payload:
                    return payload.get("fixed")
        response_texts = [block.text for block in response.content if hasattr(block, 'text')]
        result_text = " ".join(response_texts)
        return result_text

    async def async_run(self, system:str, user:str, max_retries:int=5) -> str | None:
        try:
            response = await self.async_client.messages.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=1000,
                system=system,
                messages=[
                    {"role": "user", "content": user}
                ],
                tools=[
                    {
                        "name": self._tool_name,
                        "description": "Return the final answer under the fixed key.",
                        "input_schema": self._schema
                    }
                ],
                tool_choice={"type": "tool", "name": self._tool_name},
                extra_headers={"anthropic-beta": "tools-2024-04-04"}
            )
            return self._extract_fixed(response)
        except Exception as e:
            # sleep and retry
            if max_retries > 0:
                time.sleep(6)
                return await self.async_run(system, user, max_retries - 1)
            else:
                print(e)
        return None