from google import genai
from google.genai.types import GenerateContentConfig, HttpOptions
from pydantic import BaseModel

class CodeFormat(BaseModel):
    fixed: str
    
class GEMINI:
    def __init__(self,
                 model:str="gemini-2.5-pro",
                 temperature:float=0.0):
        from dotenv import load_dotenv
        import os
        load_dotenv()
        GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        
        self.client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options=HttpOptions(api_version="v1beta"))
        self.async_client = self.client.aio
        self.model = model
        self.temperature = temperature
    
    def _extract_fixed(self, response):
        model = getattr(response, "parsed", None)
        if model is not None:
            fixed_value = getattr(model, "fixed", None)
            if fixed_value is not None:
                return fixed_value

        fallback_text = getattr(response, "text", None)
        if fallback_text is not None:
            return fallback_text
        return None
    
    async def async_run(self, system:str, user:str):
        try:
            try:
                response = await self.async_client.models.generate_content(
                    model=self.model,
                    contents=user,
                    config=GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=CodeFormat,
                        system_instruction=system,
                        temperature=self.temperature
                    ),
                )
            except Exception:
                response = await self.async_client.models.generate_content(
                    model=self.model,
                    contents=user,
                    config=GenerateContentConfig(
                        system_instruction=system,
                        temperature=self.temperature
                    ),
                )
            return self._extract_fixed(response)
        except Exception as e:
            pass
            # print(e)
        return None