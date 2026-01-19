import re
import time
from openai import AsyncOpenAI, BadRequestError, RateLimitError
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
        
        self.async_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

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
            response = await self.async_client.responses.create(
                model=self.model,
                temperature=self.temperature,
                input=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ],
            )

            model = getattr(response, "output_parsed", None)
            if model is not None:
                fixed_value = getattr(model, "fixed", None)
                if fixed_value is not None:
                    return self._extract_code(fixed_value)

            fallback_text = getattr(response, "output_text", None)
            if fallback_text is not None:
                return self._extract_code(fallback_text)
        # except BadRequestError:
        #     pass
        # except RateLimitError:
        #     pass
            # time.sleep(self.timeout)
            # if max_retry > 0:
            #     return await self.async_run(system, user, max_retry-1)
        except Exception as e:
            print(e)
            # time.sleep(self.timeout)
            # if max_retry > 0:
            #     return await self.async_run(system, user, max_retry-1)
        return None
    