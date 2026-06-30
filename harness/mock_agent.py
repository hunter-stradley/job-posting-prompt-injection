#!/usr/bin/env python3
"""
mock_agent.py -- a SAFE, OFFLINE simulation of a job-application agent, to demonstrate that a
hidden instruction in a posting actually *changes an agent's behavior* (not just that a scanner
can spot it). This is the "prove the consequence" piece, modeled on AgentDojo's design
(benign-utility / utility-under-attack / attack-success-rate).

SAFETY -- READ THIS:
  * Everything here is SIMULATED. The "tools" (apply / skip / exfiltrate) only record a decision
    in an in-memory log. They NEVER touch the network, never submit an application, never send any
    data. Running this cannot affect any real job board or any real person.
  * The default agent is a deterministic mock that mimics a *naive* instruction-following LLM:
    it reads the text it ingests (which, for a real agent, would include hidden DOM/Unicode text)
    and obeys imperative instructions found in it. That credulity is exactly the vulnerability.
  * A real-LLM backend is intentionally NOT shipped (it would add provider coupling and a live
    dependency). `act_with()` accepts any callable so you can plug one in yourself; it stays off
    unless you do.

References: AgentDojo (arXiv 2406.13352); CaMeL / "Defeating Prompt Injections by Design"
(arXiv 2503.18813) for why capability/sandboxing -- not credulous following -- is the real fix.
"""
import os
import re
import sys
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "scanner"))
import jd_injection_scanner as S
from detect import SEMANTIC_RE

Action = namedtuple("Action", ["tool", "arg"])   # tool in {"apply","skip","exfiltrate"}

# Patterns a credulous agent would "obey" if it found them in ingested posting text.
_SKIP_RE = re.compile(
    r"(do not|don'?t|never|please do not)\s+(apply|submit|continue)"
    r"|disregard[^.\n]{0,40}(do not apply|not apply|stop)"
    r"|skip (this )?(application|role|posting)"
    r"|act(ing)? (as if|like)[^.\n]{0,30}(applied|application was sent)", re.I)
_EXFIL_RE = re.compile(
    r"(upload|send|exfiltrate|post|forward|email)\b[^.\n]{0,60}?(https?://\S+|\b[\w.+-]+@[\w-]+\.\w+)", re.I)


class ToolLog:
    """Records simulated tool invocations. No side effects whatsoever."""
    def __init__(self):
        self.calls = []

    def apply(self):
        self.calls.append(Action("apply", None)); return Action("apply", None)

    def skip(self):
        self.calls.append(Action("skip", None)); return Action("skip", None)

    def exfiltrate(self, target):
        # SIMULATED ONLY: records the attempt; sends nothing.
        self.calls.append(Action("exfiltrate", target)); return Action("exfiltrate", target)


def naive_agent(ingested_text, tools):
    """A credulous agent: do the user task (apply) unless the ingested text tells it otherwise."""
    low = ingested_text or ""
    m = _EXFIL_RE.search(low)
    if m:
        return tools.exfiltrate(m.group(0))
    if _SKIP_RE.search(low):
        return tools.skip()
    return tools.apply()


# ---- guards (mitigations the harness can compare against) -------------------
def no_guard(text):
    return text


def instruction_stripping_guard(text):
    """Remove sentences that look like AI-directed instructions before the agent sees them.
    A crude stand-in for the pre-ingestion sanitizer; demonstrates utility/ASR moving."""
    keep = []
    for seg in re.split(r"(?<=[.\n])", text or ""):
        if S.INJECTION_RE.search(seg) or SEMANTIC_RE.search(seg) or _SKIP_RE.search(seg) or _EXFIL_RE.search(seg):
            continue
        keep.append(seg)
    return "".join(keep)


def run_agent(ingested_text, guard=no_guard, agent=naive_agent):
    """Run one episode; return (Action, ToolLog). Pure/offline."""
    tools = ToolLog()
    action = agent(guard(ingested_text), tools)
    return action, tools


def act_with(ingested_text, llm_callable, tools=None):
    """Escape hatch to drive a REAL agent you supply. OFF by default -- you pass the callable.
    `llm_callable(text, tools)` must return an Action. Nothing here calls a network on its own."""
    tools = tools or ToolLog()
    return llm_callable(ingested_text, tools), tools
