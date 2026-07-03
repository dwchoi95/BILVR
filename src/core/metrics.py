import logging
import tiktoken
from codebleu import calc_codebleu


class Metrics:
    """Reference-based repair-quality metrics (no LLM inference).

    Provides the automatic metrics written to the result CSV by the repair
    pipeline: token counts, CodeBLEU against the human patch, and exact match.
    """

    def token_count(self, text:str) -> int:
        if text is None:
            return 0
        encoding = tiktoken.get_encoding("cl100k_base")
        # disallowed_special=() treats any special-token strings the model may emit
        # (e.g. Qwen's <|fim_suffix|>, <|endoftext|>) as ordinary text instead of
        # raising ValueError.
        return len(encoding.encode(str(text), disallowed_special=()))

    _LANG_MAP = {"c++": "cpp", "cpp": "cpp", "c#": "c_sharp", "csharp": "c_sharp"}
    _CODEBLEU_LANGS = {"java", "javascript", "c_sharp", "php", "c", "cpp",
                       "python", "go", "ruby", "rust"}

    def code_bleu(self, human_patch: str, llm_patch: str, language: str = "c") -> float | None:
        language = self._LANG_MAP.get(language.lower(), language.lower())
        if language not in self._CODEBLEU_LANGS:
            return None  # unsupported language (e.g. typescript) -> not measured
        if llm_patch is None or str(llm_patch).strip() == "":
            return 0.0
        logging.disable(logging.WARNING)
        try:
            return calc_codebleu([human_patch], [llm_patch], lang=language)["codebleu"]
        except Exception:
            return None  # parser unavailable / parse failure -> not measured
        finally:
            logging.disable(logging.NOTSET)

    def exact_match(self, human_patch: str, llm_patch: str, language: str = "c") -> bool:
        if llm_patch is None:
            return False
        return human_patch.strip() == llm_patch.strip()
