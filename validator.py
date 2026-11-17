import os
import json
import requests
import logging

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_URL = os.getenv("LLM_API_URL", "https://api.openai.com/v1/chat/completions")

def validate_slither_report(contract_address: str, chain_id: str, slither_output: str) -> dict:
    """
    Анализирует отчет Slither через LLM для подтверждения уязвимости
    и фильтрации ложных срабатываний.
    """
    prompt = f"""
    You are an expert Smart Contract Security Auditor.
    Analyze the following Slither static analysis output for contract {contract_address} on chain {chain_id}.
    
    Slither Output:
    {slither_output}

    Evaluate if this is a true positive critical/high severity vulnerability.
    Respond in strict JSON format with keys:
    - "is_critical": boolean (true only if real high/critical vulnerability)
    - "confidence": string ("HIGH", "MEDIUM", "LOW")
    - "summary": brief explanation of the finding
    """

    if not LLM_API_KEY:
        has_issues = len(slither_output.strip()) > 50
        return {
            "is_critical": has_issues,
            "confidence": "MEDIUM",
            "summary": "Heuristic check: potential findings detected."
        }

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1
    }

    try:
        response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            clean_content = content.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_content)
    except Exception as e:
        logging.error(f"[VALIDATOR ERROR] {e}")

    return {"is_critical": False, "confidence": "LOW", "summary": "Validation failed"}
