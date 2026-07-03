"""Retrieval-based few-shot exemplar selection (experiment #4 / RQ3).

Prior-work practice (APPatch / BM25 / CodeBERT-retrieval) selects in-context
examples by *similarity to the target*, not a fixed hand-picked pair. This module
provides that retrieval substrate for the few-shot strategy.

Design (mirrors prior-work retrieval setups):
  * Exemplar corpus = NDay+ only (``data/nday_plus.csv``) for BOTH NDay+ and
    ZeroDay+ targets. Retrieval is from the model's *known* world -- this is
    exactly the leakage channel RQ3 tests.
  * Per-language hashed TF-IDF cosine NN index over ``Vulnerable Code`` (the
    retrieval key is the query we actually have at inference time).
  * Self-exclusion: never return an exemplar whose ``CVE ID`` equals the target's,
    and skip exact-duplicate code.
  * The index is built ONCE per language (lazy) and cached on the instance.
"""
from __future__ import annotations

import csv
import re
import sys
import zlib

import numpy as np
import pandas as pd

TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]")


def tokenize(code: str):
    return TOKEN.findall(str(code))


def vectorize(docs, D, idf=None):
    """Hashed TF-IDF -> (N x D) L2-normalized float32 matrix; returns (M, idf)."""
    N = len(docs)
    tf = np.zeros((N, D), np.float32)
    for i, doc in enumerate(docs):
        for tok in tokenize(doc):
            tf[i, zlib.crc32(tok.encode()) % D] += 1.0
    if idf is None:
        df = (tf > 0).sum(0)
        idf = np.log((N + 1) / (df + 1)) + 1.0
    M = tf * idf
    norm = np.linalg.norm(M, axis=1, keepdims=True)
    norm[norm == 0] = 1.0
    return (M / norm).astype(np.float32), idf


def _norm_lang(value) -> str:
    return str(value).strip().lower()


class RetrievalExemplars:
    """Per-language TF-IDF cosine index over the NDay+ corpus' ``Vulnerable Code``.

    Parameters
    ----------
    corpus_path : str
        Path to the NDay+ corpus CSV (the "known" world). Default
        ``data/nday_plus.csv``.
    D : int
        Hashed feature dimension for the TF-IDF vectorizer.
    """

    def __init__(self, corpus_path: str = "data/nday_plus.csv", D: int = 4096):
        self.corpus_path = corpus_path
        self.D = D
        self._corpus: pd.DataFrame | None = None
        # lazy per-language cache: lang -> (rows_df_reset, matrix, idf)
        self._index: dict[str, tuple[pd.DataFrame, np.ndarray, np.ndarray]] = {}

    # ------------------------------------------------------------------ corpus
    def _load_corpus(self) -> pd.DataFrame:
        if self._corpus is None:
            # CSV fields are large; lift the field-size cap and keep raw strings.
            csv.field_size_limit(sys.maxsize)
            df = pd.read_csv(self.corpus_path, keep_default_na=False, engine="c")
            df["__lang"] = df["Programming Language"].map(_norm_lang)
            self._corpus = df
        return self._corpus

    # ------------------------------------------------------------ build index
    def _ensure_index(self, lang: str) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
        """Build (once) and return the per-language (rows, matrix, idf) index."""
        if lang not in self._index:
            corpus = self._load_corpus()
            rows = corpus[corpus["__lang"] == lang].reset_index(drop=True)
            if len(rows) == 0:
                self._index[lang] = (rows, np.zeros((0, self.D), np.float32), None)
            else:
                M, idf = vectorize(rows["Vulnerable Code"].tolist(), self.D)
                self._index[lang] = (rows, M, idf)
        return self._index[lang]

    # --------------------------------------------------------------- retrieve
    def top_k(
        self,
        target_row: pd.Series | dict,
        k: int = 2,
        exclude_cve: str | None = None,
    ) -> list[pd.Series]:
        """Return the ``k`` most similar NDay+ rows to ``target_row``.

        Similarity = TF-IDF cosine over ``Vulnerable Code`` within the target's
        programming language. Self-exclusion drops any exemplar whose ``CVE ID``
        equals ``exclude_cve`` (defaults to the target's own ``CVE ID``) and any
        exact-duplicate ``Vulnerable Code``.
        """
        if k <= 0:
            return []
        lang = _norm_lang(target_row["Programming Language"])
        rows, M, idf = self._ensure_index(lang)
        if len(rows) == 0:
            return []

        if exclude_cve is None:
            exclude_cve = str(target_row.get("CVE ID", ""))
        target_code = str(target_row["Vulnerable Code"])

        # Project the single query into the same hashed TF-IDF space (reuse idf).
        q, _ = vectorize([target_code], self.D, idf)
        sims = (M @ q[0]).astype(np.float32)  # (N,) cosine

        order = np.argsort(-sims)  # descending similarity
        out: list[pd.Series] = []
        seen_cves: set[str] = set()
        seen_codes: set[str] = set()
        for j in order:
            cand = rows.iloc[int(j)]
            cve = str(cand["CVE ID"])
            code = str(cand["Vulnerable Code"])
            if exclude_cve and cve == exclude_cve:  # self-exclusion
                continue
            if code == target_code:                 # exact-duplicate of the target
                continue
            # Diversify exemplars: one row per CVE, and no exact-duplicate code
            # (a single CVE has many file/hunk rows; two of them are redundant
            # as separate few-shot examples).
            if cve in seen_cves or code in seen_codes:
                continue
            seen_cves.add(cve)
            seen_codes.add(code)
            out.append(cand)
            if len(out) >= k:
                break
        return out
