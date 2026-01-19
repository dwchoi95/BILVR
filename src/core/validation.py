import logging
import tiktoken
from codebleu import calc_codebleu

from ..llms import GPT
from ..prompts import PromptManager
from ..utils import TED


class Validation:
    def token_count(self, text:str) -> int:
        if text is None:
            return 0
        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(str(text)))

    def code_bleu(self, human_patch: str, llm_patch: str, language: str = "c") -> float:
        language = language.lower()
        if language == "c++":
            language = "cpp"
        if llm_patch is None or llm_patch.strip() == "":
            return 0.0
        logging.disable(logging.WARNING)
        try:
            return calc_codebleu(
                [human_patch],
                [llm_patch],
                lang=language
            )["codebleu"]
        finally:
            logging.disable(logging.NOTSET)

    def exact_match(self, human_patch: str, llm_patch: str, language: str = "c") -> bool:
        # ted = TED(language)
        # distance = ted.run(human_patch, llm_patch)
        # if distance == 0:
        #     return True
        # return False
        if llm_patch is None:
            return False
        return human_patch.strip() == llm_patch.strip()

    async def llm_eval(
        self,
        vulnerable_code: str,
        additional_information: str,
        human_patch: str,
        llm_patch: str
    ) -> bool:
        if llm_patch is None or type(llm_patch)!=str or llm_patch.strip() == "":
            return False
        pm = PromptManager()
        system = pm.render(file="src/prompts/validation/system.md")
        user = pm.render(
            file="src/prompts/validation/user.md",
            vulnerable_code=vulnerable_code,
            additional_information=additional_information,
            human_patch=human_patch,
            llm_patch=llm_patch,
        )
        model = GPT(model="gpt-4o-mini")
        return await model.async_run(system, user)
