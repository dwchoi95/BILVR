import re
from openai import OpenAI, AsyncOpenAI, OpenAIError, BadRequestError
from pydantic import BaseModel

class CodeFormat(BaseModel):
    fixed: str
    
class GPT:
    def __init__(self,
                 model:str="gpt-5",
                 temperature:float=0.0):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.async_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.temperature = temperature

    def _extract_code(self, text: str | None) -> str | None:
        if not text:
            return text
        match = re.search(r"<fixed_code[^>]*>(.*?)</fixed_code>", text, re.DOTALL)
        if match:
            return match.group(1).strip("\n\r")
        return text

    async def async_run(self, system:str, user:str):
        try:
            try:
                response = await self.async_client.responses.parse(
                    model=self.model,
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
        except Exception as e:
            # print(e)
            pass
        return None