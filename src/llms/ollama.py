import os
import re
import asyncio
import httpx


class OLLAMA:
    """Backend for locally-hosted models served via Ollama (LOCAL_API_URL).

    Same interface as GPT/CLAUDE: async_run(system, user) -> str | None.
    Used for the open-weight models in the matrix (e.g. qwen3-coder, gemma, codellama).
    """

    def __init__(self,
                 model: str = "codellama:7b",
                 temperature: float = 0.0,
                 timeout: int = 10,
                 max_tokens: int | None = None,
                 think: bool = False,
                 request_timeout: float = 600.0):
        from dotenv import load_dotenv
        load_dotenv()
        base_url = os.getenv("OLLAMA_API_URL") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens or int(os.getenv("OLLAMA_NUM_PREDICT", "8192"))
        self.think = think
        self.request_timeout = request_timeout
        self.last_raw_content: str | None = None
        self.last_thinking: str | None = None
        self.last_eval_count: int | None = None

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

    async def async_run(self, system: str, user: str, max_retry: int = 5) -> str | None:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "think": self.think,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
            message = data.get("message") or {}
            content = message.get("content")
            self.last_raw_content = content
            self.last_thinking = message.get("thinking")
            self.last_eval_count = data.get("eval_count")
            return self._extract_code(content)
        except httpx.HTTPStatusError as e:
            # 4xx usually means a bad endpoint/model name and should not burn
            # minutes in exponential backoff retries.
            if 400 <= e.response.status_code < 500:
                print(f"[OLLAMA HTTPStatusError] {e}")
                return None
            if max_retry > 0:
                await asyncio.sleep(self.timeout * (2 ** (5 - max_retry)))
                return await self.async_run(system, user, max_retry - 1)
            print(f"[OLLAMA transient error, retries exhausted] {e}")
            return None
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            if max_retry > 0:
                await asyncio.sleep(self.timeout * (2 ** (5 - max_retry)))
                return await self.async_run(system, user, max_retry - 1)
            print(f"[OLLAMA transient error, retries exhausted] {e}")
            return None
        except Exception as e:
            print(f"[OLLAMA unexpected error] {e}")
            if max_retry > 0:
                await asyncio.sleep(self.timeout)
                return await self.async_run(system, user, max_retry - 1)
            return None
