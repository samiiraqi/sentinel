"""Orchestrator: runs every agent on a folder and merges one report.

READ-ONLY: it only calls each agent's scan_directory (secrets, terraform,
dependencies, config_yaml, sast), which never changes files. It adds no scanning logic of its own. Findings already hold
redacted values only; nothing raw is added here. If one agent fails, the
others still run and the failure is recorded in the report.

NETWORK: the dependencies agent contacts online vulnerability databases
(package names and versions only). With --offline it refuses to run and is
reported as failed with the reason; the other agents run as usual.

Usage: python -m orchestrator.orchestrator <folder> [--exclude TEXT ...] [--offline]
Exit code: 0 = every agent ran and found nothing, 1 = findings,
2 = invalid folder or ANY agent failed (the report, with all findings, is
still printed), so a partial scan never looks clean.
"""

import argparse
import dataclasses
import json
import os
import sys

from agents.config_yaml import agent as config_yaml_agent
from agents.dependencies import agent as dependencies_agent
from agents.sast import agent as sast_agent
from agents.secrets import agent as secrets_agent
from agents.terraform import agent as terraform_agent
from shared.models import SEVERITIES, Finding

# Agent name -> scan function. Each takes (path, exclude) and returns Findings.
AGENTS = {
    secrets_agent.AGENT_NAME: secrets_agent.scan_directory,
    terraform_agent.AGENT_NAME: terraform_agent.scan_directory,
    dependencies_agent.AGENT_NAME: dependencies_agent.scan_directory,
    config_yaml_agent.AGENT_NAME: config_yaml_agent.scan_directory,
    sast_agent.AGENT_NAME: sast_agent.scan_directory,
}

# Agents that contact the network. Only these get the `offline` flag.
NETWORK_AGENTS = {dependencies_agent.AGENT_NAME}

# rule_id -> severity. Overrides what the agent reported.
# Written as (rule_id, severity) pairs: the usual dict-literal form would
# make the anthropic-api-key line look like a hard-coded key to our own
# secrets scan in CI.
SEVERITY_RULES = dict([
    # secrets agent
    ("private-key", "critical"),
    ("aws-access-key-id", "critical"),
    ("anthropic-api-key", "critical"),
    ("generic-secret-assignment", "high"),
    # terraform agent (Checkov)
    ("CKV_AWS_24", "high"),  # SSH open to 0.0.0.0/0
    ("CKV_AWS_20", "high"),  # public-read S3 bucket
    ("CKV_AWS_3", "medium"),  # unencrypted EBS volume
    ("CKV_AZURE_3", "medium"),  # storage account allows HTTP
    # config_yaml agent (Checkov: Kubernetes, Dockerfile, GitHub Actions)
    ("CKV_K8S_16", "high"),  # privileged container
    ("CKV_K8S_2", "high"),  # admits privileged containers
    ("CKV_K8S_19", "high"),  # shares the host network
    ("CKV_K8S_4", "high"),  # admits host network
    ("CKV_K8S_27", "high"),  # docker socket exposed to a container
    ("CKV_GHA_2", "high"),  # shell injection in a workflow run step
    ("CKV_GHA_3", "high"),  # curl with secrets in a workflow
    # sast agent (Bandit, Python)
    ("B602", "high"),  # subprocess call with shell=True
    ("B605", "high"),  # process started with a shell (e.g. os.system)
    ("B307", "high"),  # eval
    ("B301", "high"),  # pickle loads untrusted data
    ("B506", "high"),  # yaml.load without a safe loader
])

_RANK = {sev: i for i, sev in enumerate(reversed(SEVERITIES))}  # critical = 0


def apply_severity(finding: Finding) -> Finding:
    """Return the finding with SEVERITY_RULES applied (unknown rule_ids unchanged)."""
    severity = SEVERITY_RULES.get(finding.rule_id)
    if severity is None or severity == finding.severity:
        return finding
    return dataclasses.replace(finding, severity=severity)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Critical first, then high, medium, low; then by file and line."""
    return sorted(findings, key=lambda f: (_RANK[f.severity], f.file, f.line))


def run_all(path: str, exclude: tuple[str, ...] = (), offline: bool = False) -> dict:
    """Run every agent and return one merged report.

    With offline=True, network agents refuse to run and show as failed.
    """
    if not os.path.isdir(path):
        raise NotADirectoryError(os.path.abspath(path))

    agents = {}
    findings = []
    for name, scan in AGENTS.items():
        kwargs = {"exclude": tuple(exclude)}
        if name in NETWORK_AGENTS:
            kwargs["offline"] = offline
        try:
            found = [apply_severity(f) for f in scan(path, **kwargs)]
        except Exception as exc:  # one failing agent must not stop the others
            agents[name] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "count": 0}
            continue
        agents[name] = {"status": "ok", "error": None, "count": len(found)}
        findings.extend(found)

    findings = sort_findings(findings)
    by_severity = {sev: 0 for sev in reversed(SEVERITIES)}
    for f in findings:
        by_severity[f.severity] += 1

    return {
        "scanned_path": os.path.abspath(path),
        "agents": agents,
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_agent": {name: info["count"] for name, info in agents.items()},
        },
        "findings": [f.to_dict() for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m orchestrator.orchestrator",
        description="Run all Sentinel agents (read-only) and print one merged report.",
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip folders/files whose path contains TEXT (repeatable)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="do not contact the network: network agents refuse to run and are reported as failed",
    )
    args = parser.parse_args(argv)

    try:
        report = run_all(args.folder, exclude=tuple(args.exclude), offline=args.offline)
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2

    # The full report (including any findings) is always printed first.
    print(json.dumps(report, indent=2))
    if any(info["status"] == "failed" for info in report["agents"].values()):
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
