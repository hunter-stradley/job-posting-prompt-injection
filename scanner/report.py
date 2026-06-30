#!/usr/bin/env python3
"""
report.py -- serialize detector findings to SARIF 2.1.0 (and plain JSON).

SARIF (Static Analysis Results Interchange Format) is the lingua franca for code-scanning
dashboards (GitHub code scanning, etc.). Emitting it lets posting-injection findings flow into the
same pipelines a security team already runs. Every rule is mapped to OWASP LLM01:2025 (Prompt
Injection) and tagged with our own vector taxonomy.
"""
import json

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
OWASP_LLM01 = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
TOOL_NAME = "job-posting-prompt-injection"
TOOL_VERSION = "0.2.0"

# severity (our taxonomy) -> SARIF level
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "informational": "note"}


def _rule_id(vector):
    return f"jdpi/{vector}"


def _rule(vector):
    return {
        "id": _rule_id(vector),
        "name": vector,
        "shortDescription": {"text": f"Job-posting injection vector: {vector}"},
        "helpUri": OWASP_LLM01,
        "properties": {"owasp": "LLM01:2025", "category": "prompt-injection", "vector": vector},
    }


def to_sarif(items):
    """items: list of {"source": str, "findings": [(vector, evidence, severity, confidence), ...]}."""
    rules, seen = [], set()
    results = []
    for item in items:
        source = item.get("source", "input")
        for f in item.get("findings", []):
            vector, evidence, severity = f[0], f[1], f[2]
            confidence = f[3] if len(f) > 3 else "n/a"
            if vector not in seen:
                seen.add(vector)
                rules.append(_rule(vector))
            results.append({
                "ruleId": _rule_id(vector),
                "level": _LEVEL.get(severity, "warning"),
                "message": {"text": f"{vector}: {evidence}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": source}}}],
                "properties": {"severity": severity, "confidence": confidence},
            })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/hunter-stradley/job-posting-prompt-injection",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def to_json(items):
    """A flatter, human-friendly JSON view (not SARIF)."""
    return {"tool": TOOL_NAME, "version": TOOL_VERSION, "items": [
        {"source": it.get("source", "input"),
         "findings": [{"vector": f[0], "evidence": f[1], "severity": f[2],
                       "confidence": f[3] if len(f) > 3 else None} for f in it.get("findings", [])]}
        for it in items]}


def dumps(items, fmt):
    if fmt == "sarif":
        return json.dumps(to_sarif(items), indent=2, ensure_ascii=False)
    if fmt == "json":
        return json.dumps(to_json(items), indent=2, ensure_ascii=False)
    raise ValueError(f"unknown format: {fmt}")
