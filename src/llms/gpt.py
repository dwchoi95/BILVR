import re
import asyncio
from openai import AsyncOpenAI, BadRequestError, RateLimitError, APITimeoutError, APIConnectionError, InternalServerError
from pydantic import BaseModel

class CodeFormat(BaseModel):
    fixed: str
    
class GPT:
    def __init__(self,
                 model:str="gpt-3.5-turbo",
                 temperature:float=0.0,
                 timeout:int=10,
                 reasoning_effort:str="none"):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

        self.async_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        # GPT-5.x / o-series are reasoning models: their "thinking" is controlled by
        # reasoning effort and they reject a custom temperature. Newer models
        # (e.g. gpt-5.4-nano) take none/low/medium/high/xhigh and REJECT the older
        # "minimal"; "none" = reasoning off (our thinking-off equivalent). Non-reasoning
        # models (gpt-4o, gpt-3.5) take temperature and ignore reasoning.
        self.reasoning_effort = reasoning_effort
        self.is_reasoning = model.startswith(("gpt-5", "o1", "o3", "o4"))

    def _extract_code(self, text: str | None) -> str | None:
        if not text:
            return text
        match = re.search(r"<fixed_code[^>]*>(.*?)</fixed_code>", text, re.DOTALL)
        if match:
            return match.group(1).strip("\n\r")
        fenced = re.search(r"```[a-zA-Z0-9_+\-]*\s*\n?(.*?)```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip("\n\r")
        return text

    async def async_run(self, system:str, user:str, max_retry:int=5) -> str | None:
        try:
            kwargs = {
                "model": self.model,
                "input": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            if self.is_reasoning:
                # Minimal reasoning ("thinking off" equivalent); no temperature.
                kwargs["reasoning"] = {"effort": self.reasoning_effort}
            else:
                kwargs["temperature"] = self.temperature
            response = await self.async_client.responses.create(**kwargs)

            model = getattr(response, "output_parsed", None)
            if model is not None:
                fixed_value = getattr(model, "fixed", None)
                if fixed_value is not None:
                    return self._extract_code(fixed_value)

            fallback_text = getattr(response, "output_text", None)
            if fallback_text is not None:
                return self._extract_code(fallback_text)
        except BadRequestError as e:
            # Non-retryable (e.g. context too long, content filter): record as no patch.
            print(f"[GPT BadRequestError] {e}")
            return None
        except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError) as e:
            # Transient: exponential backoff retry.
            if max_retry > 0:
                await asyncio.sleep(self.timeout * (2 ** (5 - max_retry)))
                return await self.async_run(system, user, max_retry - 1)
            print(f"[GPT transient error, retries exhausted] {e}")
            return None
        except Exception as e:
            print(f"[GPT unexpected error] {e}")
            if max_retry > 0:
                await asyncio.sleep(self.timeout)
                return await self.async_run(system, user, max_retry - 1)
            return None
        return None
