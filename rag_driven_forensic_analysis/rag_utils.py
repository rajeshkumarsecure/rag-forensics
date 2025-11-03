#!/usr/bin/env python3
# Program is developed on Ubuntu 22.04.2 and Python 3.10.
# Utility functions for RAG-driven forensic analysis, including tokenization, similarity computation, and re-ranking.
# Version: 1.0

import json
import math
from typing import Any, Dict, Set, List, Tuple, Iterable, Callable
import re


# -----------------------------
# 0) Utility: Min-max normalize
# ---------------------------

def minmax_normalize(values: List[float]) -> List[float]:
    if not values:
        return []
    vmin, vmax = min(values), max(values)
    if abs(vmax - vmin) < 1e-12:
        return [0.0 for _ in values]  # avoid division by zero; all equal scores
    return [(v - vmin) / (vmax - vmin) for v in values]

# ----------------------------------------------
# 1) Schema-agnostic tokenization for indicators
# ----------------------------------------------

def default_value_normalizer(s: str) -> str:
    """
    Normalize values for token matching without domain assumptions.
    - Trim whitespace
    - Collapse internal spaces
    - Leave case as-is by default (to preserve canonical facets like ESTABLISHED|Outgoing|TCP)
    """
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    return s


def indicators_to_tokens(
    indicators: Dict[str, Any],
    *,
    include_false: bool = False,
    include_none: bool = False,
    lowercase_keys: bool = False,
    lowercase_values: bool = False,
    key_whitelist: Iterable[str] | None = None,
    key_blacklist: Iterable[str] | None = None,
    key_renames: Dict[str, str] | None = None,
    value_normalizer: Callable[[str], str] = default_value_normalizer,
) -> Set[str]:
    """
    Convert ANY indicators dict (nested, lists, scalars) into a set of canonical tokens.

    Tokens are 'path=value' for scalars and booleans (True by default).
    Lists produce one token per element 'path=item'.
    Nested dicts are flattened with dot paths ('a.b.c=value').

    No domain-specific hardcoding; everything is discovered dynamically.

    Parameters:
    - include_false: include 'key=false' tokens if False values should affect matching.
    - include_none: include 'key=null' tokens if None values should affect matching.
    - lowercase_keys/values: optional normalization if you need case-insensitive matching.
    - key_whitelist: only include these keys (exact or prefix match).
    - key_blacklist: exclude these keys (exact or prefix match).
    - key_renames: map certain keys to new names (e.g., normalize schema churn).
    - value_normalizer: function to normalize scalar values as strings.

    Returns:
    - Set[str] tokens.
    """
    tokens: Set[str] = set()

    def allow_key(path: str) -> bool:
        if key_whitelist:
            # allow if path == whitelist item or starts with any whitelist prefix
            if not any(path == w or path.startswith(w + ".") for w in key_whitelist):
                return False
        if key_blacklist:
            if any(path == b or path.startswith(b + ".") for b in key_blacklist):
                return False
        return True

    def rename_key(path: str) -> str:
        if not key_renames:
            return path
        # rename exact match or prefix segments
        for old, new in key_renames.items():
            if path == old:
                return new
            if path.startswith(old + "."):
                return new + path[len(old):]
        return path

    def norm_key(k: str) -> str:
        k = k.strip()
        return k.lower() if lowercase_keys else k

    def norm_value_any(v: Any) -> str:
        if isinstance(v, str):
            s = value_normalizer(v)
            return s.lower() if lowercase_values else s
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "null"
        return value_normalizer(str(v))

    def add_token(path: str, v: Any):
        path = rename_key(norm_key(path))
        if not allow_key(path):
            return

        # Scalars
        if isinstance(v, (str, int, float)):
            val = norm_value_any(v)
            tokens.add(f"{path}={val}")
            return

        # Booleans: include True by default, optionally include False
        if isinstance(v, bool):
            if v or include_false:
                val = norm_value_any(v)
                tokens.add(f"{path}={val}")
            return

        # None: optional
        if v is None:
            if include_none:
                tokens.add(f"{path}=null")
            return

        # Lists: emit one token per element; if dict elements, flatten recursively with same path
        if isinstance(v, list):
            for el in v:
                if isinstance(el, (str, int, float, bool)) or el is None:
                    val = norm_value_any(el)
                    # Only include False/None based on flags
                    if (el is False and not include_false) or (el is None and not include_none):
                        continue
                    tokens.add(f"{path}={val}")
                elif isinstance(el, dict):
                    # Flatten dict elements with the same path (no index)
                    for k2, v2 in el.items():
                        add_token(f"{path}.{norm_key(k2)}", v2)
                else:
                    # Fallback scalar repr
                    tokens.add(f"{path}={norm_value_any(el)}")
            return

        # Dicts: flatten with dot path
        if isinstance(v, dict):
            for k, v2 in v.items():
                add_token(f"{path}.{norm_key(k)}", v2)
            return

        # Fallback for unknown types
        tokens.add(f"{path}={norm_value_any(v)}")

    # Kick off flattening at root for every key
    for k, v in (indicators or {}).items():
        add_token(norm_key(k), v)

    return tokens


def indicators_to_tokens_safe(
    indicators: Dict[str, Any],
    *,
    include_false: bool = False,
    include_none: bool = False,
    lowercase_keys: bool = False,     # keep keys’ case (usually fine)
    lowercase_values: bool = False,   # preserve facet case
    key_whitelist: Iterable[str] | None = None,
    key_blacklist: Iterable[str] | None = None,
    key_renames: Dict[str, str] | None = None,
    value_normalizer: Callable[[str], str] = default_value_normalizer,
) -> Set[str]:
    """
    Opinionated wrapper with safe defaults for your security indicators.
    Adjust args if/when your matching rules evolve.
    """
    return indicators_to_tokens(
        indicators,
        include_false=include_false,
        include_none=include_none,
        lowercase_keys=lowercase_keys,
        lowercase_values=lowercase_values,
        key_whitelist=key_whitelist,
        key_blacklist=key_blacklist,
        key_renames=key_renames,
        value_normalizer=value_normalizer,
    )


# ------------------------------------------------------------
# Token helpers (reusing your schema-agnostic tokenization)
# ------------------------------------------------------------
def get_indicator_tokens_from_payload(payload: Dict[str, Any]) -> Set[str]:
    """
    Prefer cached tokens; otherwise compute from payload['indicators'] using your function.
    """
    if not payload:
        return set()
    cached = payload.get("indicator_tokens")
    if isinstance(cached, list) and cached:
        return set(cached)
    inds = payload.get("indicators") or {}
    return indicators_to_tokens_safe(inds)


# ------------------------------------
# 2) Set similarity (Precision/Jaccard)
# ------------------------------------

def precision_match_ratio(query_tokens: Set[str], doc_tokens: Set[str]) -> float:
    """Fraction of query tokens present in the doc tokens."""
    if not query_tokens:
        return 1.0
    return len(query_tokens & doc_tokens) / len(query_tokens)


def jaccard_similarity(query_tokens: Set[str], doc_tokens: Set[str]) -> float:
    """Intersection over union of token sets."""
    union = query_tokens | doc_tokens
    if not union:
        return 0.0
    return len(query_tokens & doc_tokens) / len(union)


# -----------------------------
# 3) BM25 helpers (Okapi BM25)
# -----------------------------
def tokenize(text: str) -> List[str]:
    """
    Simple tokenizer: lowercases and keeps alphanumerics, plus '|' and '+' etc.
    Tune as needed for your domain (Meterpreter, RWX, TCP terms).
    """
    text = (text or "").lower()
    return re.findall(r"[a-z0-9\|\+_]+", text)


def compute_bm25_idf(corpus_tokens: List[List[str]]) -> Dict[str, float]:
    """
    Compute IDF per term over the candidate corpus.
    This is suitable for re-ranking (we're not building a global index here).
    """
    N = len(corpus_tokens)
    df: Dict[str, int] = {}
    for doc in corpus_tokens:
        unique_terms = set(doc)
        for t in unique_terms:
            df[t] = df.get(t, 0) + 1
    idf = {}
    # Okapi with 0.5 smoothing
    for t, n_t in df.items():
        idf[t] = math.log((N - n_t + 0.5) / (n_t + 0.5) + 1e-12)
    return idf


def bm25_score_single(
    query_tokens: List[str],
    doc_tokens: List[str],
    idf: Dict[str, float],
    avgdl: float,
    k1: float = 1.5,
    b: float = 0.75
) -> float:
    """
    Compute BM25 score for one doc vs query.
    """
    tf: Dict[str, int] = {}
    for t in doc_tokens:
        tf[t] = tf.get(t, 0) + 1

    dl = len(doc_tokens)
    score = 0.0
    for qt in set(query_tokens):
        if qt not in idf:
            continue
        freq = tf.get(qt, 0)
        denom = freq + k1 * (1 - b + b * (dl / max(1, avgdl)))
        score += idf[qt] * ((freq * (k1 + 1)) / max(1e-12, denom))
    return score


def compute_bm25_scores(query_text: str, doc_texts: List[str]) -> Tuple[List[float], Dict[str, float]]:
    """
    Compute BM25 scores for a list of doc_texts against query_text.
    Returns: (scores_per_doc, idf_dict)
    """
    query_tokens = tokenize(query_text)
    corpus_tokens = [tokenize(t) for t in doc_texts]
    idf = compute_bm25_idf(corpus_tokens)
    avgdl = sum(len(toks) for toks in corpus_tokens) / max(1, len(corpus_tokens))
    bm25_scores = [bm25_score_single(query_tokens, dt, idf, avgdl) for dt in corpus_tokens]
    return bm25_scores, idf


# ---------------------------------------------------
# 4) Final re-ranking: dense + BM25 + jaccard ratio
# ---------------------------------------------------
def rerank_with_bm25_and_set_similarity(
    points,                   # List[ScoredPoint] from Qdrant
    query_text: str,             # e.g., "ESTABLISHED Outgoing TCP connection"
    query_indicators: Dict[str, Any],  # structured indicators from your memory dump
    *,
    include_tags_in_bm25: bool = True,
    weights: Dict[str, float] = None    # blend weights for 'dense', 'bm25', 'jacc' (jaccard similarity)
):
    """
    Re-ranks Qdrant candidates using:
      - dense similarity (normalized),
      - BM25 (normalized) over payload text (+tags, if enabled),
      - jaccard set similarity of indicators (no weights per indicator).
    """
    if weights is None:
        # Default blend; adjust as needed
        weights = {"dense": 0.5, "bm25": 0.3, "jacc": 0.2}

    # 1) Prepare doc texts for BM25
    doc_texts = []
    dense_scores = []
    docs_meta = []

    for p in points:
        payload = p.payload or {}
        base_text = payload.get("text") or payload.get("payload_text") or ""
        if include_tags_in_bm25:
            tags = payload.get("tags") or []
            # join tags to text to boost keyword overlap (Meterpreter, RWX, TCP, etc.)
            full_text = base_text + " " + " ".join(tags)
        else:
            full_text = base_text

        doc_texts.append(full_text)
        dense_scores.append(float(p.score))
        docs_meta.append({
            "id": p.id,
            "payload": payload
        })

    # 2) BM25
    bm25_scores, _idf = compute_bm25_scores(query_text, doc_texts)

    # 3) Normalize dense + BM25
    dense_norm = minmax_normalize(dense_scores)
    bm25_norm = minmax_normalize(bm25_scores)

    # 4) Indicator tokens (schema-agnostic)
    q_tokens = indicators_to_tokens_safe(query_indicators)

    results = []
    for i, meta in enumerate(docs_meta):
        doc_inds = meta["payload"].get("indicators") or {}
        d_tokens = indicators_to_tokens_safe(doc_inds)
        precision = precision_match_ratio(q_tokens, d_tokens)
        jacc = jaccard_similarity(q_tokens, d_tokens)  # optional, for debugging/analytics

        final_score = (
            weights["dense"]    * dense_norm[i] +
            weights["bm25"]     * bm25_norm[i]  +
            weights["jacc"]     * jacc
        )

        results.append({
            "id": meta["id"],
            "final_score": final_score,
            "dense_similarity": dense_scores[i],
            "dense_norm": dense_norm[i],
            "bm25_score": bm25_scores[i],
            "bm25_norm": bm25_norm[i],
            "precision_ratio": precision,
            "jaccard": jacc,
            "classification": meta["payload"].get("classification"),
            "text_snippet": (meta["payload"].get("text") or "")[:160],
            "dtoks": sorted(d_tokens),
            "payload": meta["payload"]
        })

    # 5) Sort by final score (desc). For strict facet requirements, filter before this step.
    results.sort(key=lambda r: r["final_score"], reverse=True)
    return results



# ------------------------------------------------------------
# Set similarity helpers (no weights)
# ------------------------------------------------------------


def compute_match_sets(query_tokens: Set[str], candidate_tokens: Set[str]) -> Tuple[List[str], List[str]]:
    matched = sorted(list(query_tokens & candidate_tokens))
    missing = sorted(list(query_tokens - candidate_tokens))
    return matched, missing

# ------------------------------------------------------------
# Eligibility & selection (metric-agnostic)
# ------------------------------------------------------------
def select_top_candidates_by_similarity(
    ranked: List[Dict[str, Any]],
    query_tokens: Set[str],
    *,
    similarity_metric: str = "jaccard",  # "jaccard" | "precision"
    min_threshold: float = 0.75,
    exact_match_mode: str = "equality",  # "equality" | "coverage"
    k: int = 2,
    allow_fallback: bool = False,
    min_final_score: float = 0.0
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Compute similarity per candidate and mark eligibility:
      - similarity_metric: "jaccard" or "precision".
      - min_threshold: gate for eligibility.
      - exact_match_mode:
          * "equality": candidate_tokens == query_tokens  (strict)
          * "coverage": candidate_tokens ⊇ query_tokens   (all query tokens present)
    Returns selected candidates and a summary.
    """
    def sim_val(cand_toks: Set[str]) -> float:
        if similarity_metric == "precision":
            return precision_match_ratio(query_tokens, cand_toks)
        # default: jaccard
        return jaccard_similarity(query_tokens, cand_toks)

    def is_exact(cand_toks: Set[str]) -> bool:
        if exact_match_mode == "coverage":
            return query_tokens.issubset(cand_toks)
        # default: equality (strict)
        return cand_toks == query_tokens

    eligible, ineligible = [], []

    for r in ranked:
        cand_tokens = set(r.get("dtoks", []))
        sim = sim_val(cand_tokens)
        r["_similarity"] = sim
        r["_exact_match"] = is_exact(cand_tokens)
        r["_eligible"] = bool(sim >= min_threshold and r.get("final_score", 0.0) >= min_final_score)
        (eligible if r["_eligible"] else ineligible).append(r)

    # Sort: primary by final_score, secondary by similarity
    eligible.sort(key=lambda x: (x.get("final_score", 0.0), x["_similarity"]), reverse=True)
    ineligible.sort(key=lambda x: (x.get("final_score", 0.0), x["_similarity"]), reverse=True)

    selected = eligible[:k]
    if not selected and allow_fallback and ineligible:
        # present the nearest ineligible candidate ONLY for transparency; LLM must not use it for "Threat"
        selected = [ineligible[0]]

    rag_match_status = "none"
    if selected:
        if any(r["_exact_match"] for r in selected):
            rag_match_status = "exact"
        else:
            rag_match_status = "high_quality"

    summary = {
        "similarity_metric": similarity_metric,
        "min_threshold": min_threshold,
        "exact_match_mode": exact_match_mode,
        "allow_fallback": allow_fallback,
        "eligible_count": len(eligible),
        "selected_count": len(selected),
        "rag_match_status": rag_match_status,
        "top_similarity": (eligible[0]["_similarity"] if eligible else (selected[0]["_similarity"] if selected else None))
    }
    return selected, summary

# ------------------------------------------------------------
# Context item (generic; no domain hardcoding)
# ------------------------------------------------------------
def make_context_item_generic(
    r: Dict[str, Any],
    query_tokens: Set[str]
) -> Dict[str, Any]:
    cand_tokens = set(r.get("dtoks", []))
    matched, missing = compute_match_sets(query_tokens, cand_tokens)
    return {
        "id": r["id"],
        "classification": r.get("classification"),
        "scores": {
            "final": round(r.get("final_score", 0.0), 3),
            "dense_norm": round(r.get("dense_norm", 0.0), 3),
            "bm25_norm": round(r.get("bm25_norm", 0.0), 3),
            "similarity": round(r.get("_similarity", 0.0), 3),
            "exact_match": bool(r.get("_exact_match", False))
        },
        "eligible": bool(r.get("_eligible", False)),
        "indicator_tokens": r.get("dtoks", []),
        "matched_query_tokens": matched,
        "missing_query_tokens": missing,
        "text_snippet": r.get("text_snippet", "")
    }

# ------------------------------------------------------------
# Prompt builder (generic; no hardcoded categories)
# ------------------------------------------------------------
def build_forensics_messages(
    process_tree_json: Dict[str, Any],
    ranked: List[Dict[str, Any]],
    query_text: str,
    query_indicators: Dict[str, Any],
    *,
    similarity_metric: str = "jaccard",   # "jaccard" | "precision"
    min_threshold: float = 0.75,
    exact_match_mode: str = "equality",   # "equality" | "coverage"
    top_k: int = 2,
    allow_fallback: bool = False,
) -> List[Dict[str, str]]:
    """
    Build LLM messages with purely token-driven policies.
    No hardcoded indicator categories or domain-specific validation strings.
    """

    # Build query_tokens using your schema-agnostic tokenizer
    query_tokens: Set[str] = indicators_to_tokens_safe(query_indicators)

    # Select candidates by the chosen similarity metric/threshold
    selected, selection_summary = select_top_candidates_by_similarity(
        ranked=ranked,
        query_tokens=query_tokens,
        similarity_metric=similarity_metric,
        min_threshold=min_threshold,
        exact_match_mode=exact_match_mode,
        k=top_k,
        allow_fallback=allow_fallback
    )

    selected_context = [make_context_item_generic(r, query_tokens) for r in selected]

    # System prompt: concise and generic
    system_prompt = (
        "You are a forensic analysis assistant. Analyze the provided process tree and token-driven RAG context "
        "to identify indicators of compromise and classify threats. Use only the supplied information."
    )

    # Generic rules—no domain words, only token logic and eligibility
    rules = [
        "Use only the provided context. Do not invent facts.",
        f"Candidates are 'eligible' only if {selection_summary['similarity_metric']} >= {min_threshold:.2f}. Do NOT use ineligible candidates to determine 'Threat'.",
        f"Exact match mode: '{exact_match_mode}'.",
        "Process tree silence (no evidence) is NOT a mismatch; only explicit contradictions count as mismatches.",
        "Always list Matched vs Missing query tokens for any candidate you reference.",
        "Do not include dynamic fields (PIDs, IP Addresses, timestamps, process names, etc.) in 'observation'.",
        "Only include explicitly suspicious or confirmed malicious artifacts in technical details. Do not include benign details provided from process information.",
        "Normalize unusual ports as 'suspicious port' when appropriate.",
        "Return output in STRICT JSON only; no extra commentary.",
        "For JSON list fields, each item must be a separate string."
    ]

    # Strict output schema (unchanged, generic)
    output_schema = {
        "observation": ["<Detailed forensic observation combining process tree and RAG insights>"],
        "Technical Details": ["<Detailed technical analysis including IoCs like IPs, ports, process names, memory regions with Addresses>"],
        "Threat": "<Classification Name from RAG or your own if not found>",
        "Tactics": ["<Accurate MITRE ATT&CK Tactics based on IoC & RAG Indicators>"],
        "Reason for Tactics": ["<Why these tactics were chosen with IoC & Indicators>"],
        "Techniques": ["<Accurate MITRE ATT&CK Techniques based on IoC & RAG Indicators>"],
        "Reason for Techniques": ["<Why these techniques were chosen with IoC & Indicators>"],
        "classification": "<Malicious | Suspicious | Benign>",
        "confidence": "<Low | Medium | High>",
        "reasoning": ["<Why you classified it this way>"],
        "matched_rag_indicators": ["<Indicators from RAG that align with input>"],
        "Security Recommendations": ["<Security recommendations retrieved from RAG and generate commands to implement them with IOCs>"]
    }

    # Compose user content (generic, token-driven)
    user_content = {
        "process_tree": process_tree_json,
        "rag_query": {
            "query_text": query_text,
            "query_indicators": query_indicators,
            "query_tokens": sorted(list(query_tokens))
        },
        "selected_candidates": selected_context,
        "selection_policy": {
            "similarity_metric": similarity_metric,
            "min_threshold": min_threshold,
            "exact_match_mode": exact_match_mode,
            "allow_fallback": allow_fallback
        },
        "selection_summary": selection_summary,
        "Your task": [
            "Analyze the process tree and selected RAG candidates together.",
            "Identify correlations, anomalies, and indicajators of compromise.",
            "Validate indicator alignment (Matched vs Missing) against query_tokens.",
            "If selection_summary.rag_match_status == 'none', do not use RAG to set 'Threat'; base decisions on the process tree only.",
            "Return STRICT JSON matching the schema."
        ],
        "Rules": rules,
        "Output Format (strict)": output_schema
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_content, indent=2)}
    ]
    return messages
