import json
import httpx
import re
from openai import AsyncOpenAI, OpenAIError, BadRequestError, APITimeoutError
from pydantic import BaseModel

class CodeFormat(BaseModel):
    fixed: str
    
class GPT:
    def __init__(self,
                 model:str="gpt-3.5-turbo",
                 temperature:float=0.0,
                 timeout:int=10):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        
        self.async_client = AsyncOpenAI(api_key=OPENAI_API_KEY, timeout=3)
        self.model = model
        self.temperature = temperature
        self.timeout = 3

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

    async def async_run(self, system:str, user:str, max_retry:int=1) -> str | None:
        try:
            try:
                response = await self.async_client.responses.parse(
                    model=self.model,
                    timeout=self.timeout,
                    temperature=self.temperature,
                    input=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    text_format=CodeFormat,
                )
            except OpenAIError:
                response = await self.async_client.responses.create(
                    model=self.model,
                    timeout=self.timeout,
                    temperature=self.temperature,
                    input=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                )
            except (APITimeoutError) as e:
                import time
                if max_retry > 0:
                    time.sleep(5)
                    return await self.async_run(system, user, max_retry-1)
                return None

            model = getattr(response, "output_parsed", None)
            if model is not None:
                fixed_value = getattr(model, "fixed", None)
                if fixed_value is not None:
                    return self._extract_code(fixed_value)

            fallback_text = getattr(response, "output_text", None)
            if fallback_text is not None:
                return self._extract_code(fallback_text)
        except (APITimeoutError) as e:
            import time
            if max_retry > 0:
                time.sleep(5)
                return await self.async_run(system, user, max_retry-1)
            return None
        except Exception as e:
            print(e)
        return None

    async def async_local(self, system:str, user:str) -> str| None:
        url = "http://115.145.135.227:7220/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
        }

        payload = {
            "model": "openai/gpt-oss-120b",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            print(f"[요청 오류] {exc}")
            if exc.response is not None:
                print(f"[응답 본문]\n{exc.response.text}")
            return
        except httpx.RequestError as exc:
            print(f"[요청 오류] {exc}")
            return

        try:
            data = resp.json()
        except json.JSONDecodeError:
            print("[파싱 오류] JSON이 아닙니다.\n원문:\n", resp.text)
            return

        try:
            content = data["choices"][0]["message"]["content"]
            fixed = self._extract_code(content)
            return fixed
        except (KeyError, IndexError):
            print("\n[주의] 예상한 형태가 아닌 응답입니다. 위 Raw Response를 확인하세요.")
        
        return None