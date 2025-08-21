import os, requests, json

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("MODEL_NAME", "gpt-4o-mini")

def classify_with_llm(snippet, kind):
    if not OPENAI_API_KEY:
        return False, "missing OPENAI_API_KEY"
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": OPENAI_MODEL,
                "messages": [{"role":"user","content": f"Is this a REAL {kind} secret? Reply JSON {{\"is_secret\":true|false,\"reason\":\"...\"}}.\nSnippet:\n```{snippet[:1500]}```"}],
                "temperature": 0.0,
                "max_tokens": 150
            },
            timeout=60
        )
        content = r.json()["choices"][0]["message"]["content"]
        data = json.loads(next((s for s in [content] if s.strip().startswith("{")), "{}"))
        return bool(data.get("is_secret", False)), data.get("reason", "parsed")
    except Exception as e:
        return False, f"llm_error: {e}"

