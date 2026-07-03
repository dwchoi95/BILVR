import os
import re
import asyncio
from openai import AsyncOpenAI, APITimeoutError, APIConnectionError, InternalServerError, RateLimitError


class VLLM:
    """Backend for locally-hosted models served via vLLM's OpenAI-compatible API.

    Faster than Ollama for batched/concurrent inference. Start the server with e.g.
        vllm serve Qwen/Qwen3-Coder-30B-A3B-Instruct --port 8000
    and point LOCAL_API_URL at its /v1 endpoint (e.g. http://localhost:8000/v1).
    Same interface as GPT/CLAUDE: async_run(system, user) -> str | None.
    """

    def __init__(self,
                 model: str = "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                 temperature: float = 0.0,
                 timeout: int = 10,
                 max_tokens: int = 8192,
                 request_timeout: float = 600.0,
                 think: bool = True,
                 base_url: str | None = None):
        from dotenv import load_dotenv
        load_dotenv()
        base_url = base_url or os.getenv("LOCAL_API_URL", "http://localhost:8000/v1")
        # Accept a bare host:port and normalise to the OpenAI-compatible /v1 path.
        if not base_url.rstrip("/").endswith("/v1"):
            base_url = base_url.rstrip("/") + "/v1"
        self.async_client = AsyncOpenAI(base_url=base_url, api_key="EMPTY", timeout=request_timeout)
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens
        # think=False disables hybrid reasoning for models that support it
        # (Qwen3 / Gemma 4 style chat templates) via vLLM chat_template_kwargs.
        self.think = think

    def _extra_body(self) -> dict | None:
        if self.think:
            return None
        return {"chat_template_kwargs": {"enable_thinking": False}}

    def _extract_code(self, text: str | None) -> str | None:
        if not text:
            return text
        match = re.search(r"<fixed_code[^>]*>(.*?)</fixed_code>", text, re.DOTALL)
        if match:
            return match.group(1).strip("\n\r")
        fenced = re.search(r"```[a-zA-Z0-9_+\-]*\s*\n?(.*?)```", text, re.DOTALL)
        if fenced:
            return fenced.group(1).strip("\n\r")
        return text.strip("\n\r")

    async def async_run(self, system: str, user: str, max_retry: int = 5,
                        extract: bool = True) -> str | None:
        try:
            resp = await self.async_client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                extra_body=self._extra_body(),
            )
            content = resp.choices[0].message.content
            return self._extract_code(content) if extract else (content or "").strip()
        except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError) as e:
            if max_retry > 0:
                await asyncio.sleep(self.timeout * (2 ** (5 - max_retry)))
                return await self.async_run(system, user, max_retry - 1, extract)
            print(f"[VLLM transient error, retries exhausted] {e}")
            return None
        except Exception as e:
            print(f"[VLLM unexpected error] {e}")
            if max_retry > 0:
                await asyncio.sleep(self.timeout)
                return await self.async_run(system, user, max_retry - 1, extract)
            return None
