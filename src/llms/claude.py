import asyncio
from anthropic.types import ToolUseBlock
from anthropic import AsyncAnthropic, RateLimitError, BadRequestError

class CLAUDE:
    def __init__(self,
                 model:str="claude-3-haiku-20240307",
                 temperature:float=0.0,
                 timeout:int=10,
                 max_tokens:int=16384):  # 8192 truncated large-function patches -> None;
                                         # 16384 is the non-streaming ceiling (>16384 needs
                                         # streaming). Output is billed on actual tokens, so
                                         # raising the cap costs nothing unless used.
        from dotenv import load_dotenv
        import os
        load_dotenv()
        CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")

        self.async_client = AsyncAnthropic(api_key=CLAUDE_API_KEY)
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens
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

    async def async_run(self, system:str, user:str, max_retry:int=5) -> str | None:
        try:
            response = await self.async_client.messages.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                system=system,
                # Extended thinking is opt-in; explicitly disable it (accepted on
                # Haiku 4.5 / Sonnet 4.5-tier). Required so forced tool_choice below
                # is unambiguous and inference stays fast.
                thinking={"type": "disabled"},
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
        except BadRequestError as e:
            print(f"[CLAUDE BadRequestError] {e}")
            return None
        except RateLimitError as e:
            if max_retry > 0:
                await asyncio.sleep(self.timeout * (2 ** (5 - max_retry)))
                return await self.async_run(system, user, max_retry-1)
            print(f"[CLAUDE rate limit, retries exhausted] {e}")
            return None
        except Exception as e:
            print(f"[CLAUDE unexpected error] {e}")
            if max_retry > 0:
                await asyncio.sleep(self.timeout)
                return await self.async_run(system, user, max_retry-1)
            return None
        return None
    
    