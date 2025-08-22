import os


def can_use_llm() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def verify_with_llm_snippet(kind: str, snippet: str):
    """Placeholder: returns heuristic without calling external API.
    Later: integrate OpenAI if OPENAI_API_KEY present.
    """
    # For MVP, treat known formats as true
    reason = f"Heuristic verification for kind={kind}"
    return True, reason
