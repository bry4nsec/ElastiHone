"""Shared test fixtures and configuration."""

from __future__ import annotations

import pytest

# Sample rule content for tests
SAMPLE_SIGMA = """\
title: Test Sigma Rule
id: test-0001
description: A test Sigma rule for unit testing.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    process.name: 'cmd.exe'
    process.command_line|contains:
      - '/c whoami'
      - '/c ipconfig'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.003
"""

SAMPLE_ELASTIC = """\
{
  "name": "Test Elastic Rule",
  "rule_id": "test-0002",
  "type": "query",
  "language": "kuery",
  "query": "process.name: cmd.exe and process.command_line: *whoami*",
  "severity": "medium",
  "risk_score": 50,
  "index": ["logs-*"],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0002", "name": "Execution"},
      "technique": [
        {
          "id": "T1059",
          "name": "Command and Scripting Interpreter",
          "subtechnique": [
            {"id": "T1059.003", "name": "Windows Command Shell"}
          ]
        }
      ]
    }
  ]
}
"""

SAMPLE_EQL = """\
{
  "name": "Test EQL Rule",
  "rule_id": "test-0003",
  "type": "eql",
  "language": "eql",
  "query": "process where process.name == \\"cmd.exe\\" and process.args : \\"*whoami*\\"",
  "severity": "high",
  "risk_score": 75,
  "index": ["logs-*"],
  "threat": []
}
"""
