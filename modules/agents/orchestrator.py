"""
AI Orchestrator — the brain of Aegis.

For every Finding it receives, the orchestrator:
  1. Sends the finding to an LLM along with a set of callable "tools" (agents).
  2. The LLM decides which actions to take (it can call multiple tools per finding).
  3. The orchestrator executes the chosen tools and feeds results back to the LLM.
  4. The loop continues until the LLM issues a final explanation and stops.

Available tools the AI can invoke:
  remediate_cloud_resource  → CloudRemediationAgent
  block_network_threat      → NetworkRemediationAgent
  alert_siem                → SIEMAgent
  sandbox_user              → NetworkRemediationAgent (kick_user action)
  explain_risk              → Records a human-readable explanation (no live action)

AI Provider:
  Defaults to OpenAI if OPENAI_API_KEY is set.
  Set OPENAI_BASE_URL to use any OpenAI-compatible endpoint:
    - Ollama:    http://localhost:11434/v1   (OPENAI_API_KEY=ollama)
    - LM Studio: http://localhost:1234/v1    (OPENAI_API_KEY=lm-studio)
    - vLLM:      http://localhost:8000/v1
    - LocalAI:   http://localhost:8080/v1
    - Groq:      https://api.groq.com/openai/v1
    - Any other OpenAI-compatible API
"""

import json
import logging
from typing import Any, List

from openai import OpenAI

from config import AUTO_REMEDIATE, DRY_RUN, OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
from modules.scanners.base import Finding
from modules.agents.base import RemediationResult
from modules.agents.cloud_agent import CloudRemediationAgent
from modules.agents.network_agent import NetworkRemediationAgent
from modules.agents.siem_agent import SIEMAgent

logger = logging.getLogger(__name__)


def _get_client() -> OpenAI:
    """
    Build the LLM client from config.

    OPENAI_BASE_URL lets you swap to any OpenAI-compatible backend:
      - Leave empty → uses api.openai.com (standard OpenAI)
      - Set to Ollama / vLLM / LocalAI URL → fully local, no data leaves your network
    """
    kwargs: dict = {}
    # Only set api_key if one is provided; some local endpoints (Ollama) ignore it
    # but the openai library requires a non-empty value.
    kwargs["api_key"] = OPENAI_API_KEY or "no-key-required"
    if OPENAI_BASE_URL:
        kwargs["base_url"] = OPENAI_BASE_URL
        logger.debug(f"LLM client pointing to custom base URL: {OPENAI_BASE_URL}")
    return OpenAI(**kwargs)

# ── Tool definitions (OpenAI function-calling schema) ─────────────────────────

REMEDIATION_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "remediate_cloud_resource",
            "description": (
                "Apply an automated fix to a misconfigured cloud resource. "
                "Use for findings on AWS, Azure, or GCP — e.g., make an S3 bucket "
                "private, revoke an open security group rule, or disable public RDS access."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "block_public_access",
                            "revoke_ingress",
                            "disable_public_access",
                            "guidance_only",
                        ],
                        "description": "The specific remediation action to execute.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief justification for taking this action.",
                    },
                },
                "required": ["action", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "block_network_threat",
            "description": (
                "Respond to a network-level threat by blocking an IP address, "
                "closing an exposed port, or isolating a compromised host entirely."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["block_ip", "close_port", "isolate_host"],
                        "description": "The network containment action to execute.",
                    },
                    "reason": {"type": "string"},
                },
                "required": ["action", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sandbox_user",
            "description": (
                "Kick a specific user off the network / terminate their sessions. "
                "Use when a user account appears to be compromised or is acting maliciously."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "System username to terminate sessions for.",
                    },
                    "reason": {"type": "string"},
                },
                "required": ["username", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "alert_siem",
            "description": (
                "Forward this finding to the configured SIEM or alerting webhook. "
                "Always call this for critical or high severity findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity_justification": {
                        "type": "string",
                        "description": "Why this finding warrants a SIEM alert.",
                    },
                },
                "required": ["severity_justification"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_risk",
            "description": (
                "Record a human-readable explanation of the finding, the risk it poses, "
                "and manual remediation steps. Always call this as your final action."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Plain-English explanation of the risk.",
                    },
                    "manual_steps": {
                        "type": "string",
                        "description": "Step-by-step manual remediation instructions.",
                    },
                    "cli_command": {
                        "type": "string",
                        "description": "Cloud CLI command to fix this (if applicable).",
                    },
                    "terraform": {
                        "type": "string",
                        "description": "Terraform snippet to fix this (if applicable).",
                    },
                },
                "required": ["summary", "manual_steps"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are Aegis, an autonomous cloud and network security response system.

Your job:
1. Analyze the security finding provided.
2. Decide which remediation actions to take using the available tools.
3. Always call alert_siem for CRITICAL or HIGH severity findings.
4. For cloud findings (AWS/Azure/GCP), call remediate_cloud_resource if an automated fix exists.
5. For network findings, call block_network_threat to contain the threat.
6. Only call sandbox_user when a specific compromised username is identifiable.
7. Always finish by calling explain_risk with a clear summary and manual steps.

Be decisive. When a finding is clearly dangerous, act immediately.
When automated remediation is marked as dry_run, still call the tools — the system will simulate them safely."""


class AIOrchestrator:
    """
    Drives the agentic remediation loop:
    GPT decides → tools execute → results fed back → GPT continues until done.
    """

    def __init__(self, dry_run: bool = DRY_RUN, auto_remediate: bool = AUTO_REMEDIATE):
        effective_dry_run = dry_run or not auto_remediate
        self.dry_run = effective_dry_run
        self.auto_remediate = auto_remediate
        self.cloud_agent = CloudRemediationAgent(dry_run=effective_dry_run)
        self.network_agent = NetworkRemediationAgent(dry_run=effective_dry_run)
        self.siem_agent = SIEMAgent(dry_run=effective_dry_run)

    def process_finding(self, finding: Finding) -> dict:
        """Run the full agentic loop for a single finding."""
        finding_text = (
            f"Provider:         {finding.provider}\n"
            f"Resource:         {finding.resource}\n"
            f"Resource Type:    {finding.resource_type}\n"
            f"Issue:            {finding.issue}\n"
            f"Severity:         {finding.severity.upper()}\n"
            f"Details:          {json.dumps(finding.details, indent=2)}\n"
            f"Remediation Hint: {finding.remediation_hint or 'N/A'}\n"
            f"Mode:             {'DRY RUN — no live changes' if self.dry_run else 'LIVE — changes will be applied'}"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": finding_text},
        ]

        actions_taken: List[dict] = []
        explanation: dict = {}
        max_rounds = 8  # prevent infinite loops

        for round_num in range(max_rounds):
            response = _get_client().chat.completions.create(
                model=OPENAI_MODEL,
                messages=messages,
                tools=REMEDIATION_TOOLS,
                tool_choice="auto",
            )
            choice = response.choices[0]
            msg = choice.message

            # Append assistant turn (serialize tool_calls properly)
            messages.append(msg.model_dump(exclude_unset=True))

            if choice.finish_reason == "stop" or not msg.tool_calls:
                break

            # Execute each tool call the AI requested
            for tool_call in msg.tool_calls:
                func_name = tool_call.function.name
                try:
                    args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                result = self._dispatch(func_name, finding, args)
                action_record = {
                    "tool": func_name,
                    "args": args,
                    "result": result if isinstance(result, dict) else result.to_dict(),
                }
                actions_taken.append(action_record)

                if func_name == "explain_risk":
                    explanation = args

                # Feed result back so the AI can reason about what happened
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(action_record["result"]),
                })

        return {
            "finding": finding.to_dict(),
            "actions_taken": actions_taken,
            "explanation": explanation,
            "dry_run": self.dry_run,
        }

    def process_findings(self, findings: List[Finding]) -> List[dict]:
        """Process a list of findings and return all results."""
        results = []
        for finding in findings:
            try:
                result = self.process_finding(finding)
                results.append(result)
            except Exception as e:
                logger.error(f"Orchestrator failed on {finding.resource}: {e}")
                results.append({
                    "finding": finding.to_dict(),
                    "error": str(e),
                    "actions_taken": [],
                    "explanation": {},
                    "dry_run": self.dry_run,
                })
        return results

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    def _dispatch(self, tool_name: str, finding: Finding, args: dict) -> Any:
        if tool_name == "remediate_cloud_resource":
            if self.cloud_agent.can_handle(finding):
                return self.cloud_agent.remediate(finding, args.get("action", "guidance_only"))
            return {"error": "cloud_agent cannot handle this finding type"}

        elif tool_name == "block_network_threat":
            if self.network_agent.can_handle(finding):
                return self.network_agent.remediate(finding, args.get("action", "block_ip"))
            return {"error": "network_agent cannot handle this finding type"}

        elif tool_name == "sandbox_user":
            return self.network_agent.remediate(
                finding, "kick_user", username=args.get("username")
            )

        elif tool_name == "alert_siem":
            return self.siem_agent.remediate(finding, "alert")

        elif tool_name == "explain_risk":
            # No live action — the explanation is captured in the caller
            return {"status": "recorded", **args}

        return {"error": f"Unknown tool: {tool_name}"}
