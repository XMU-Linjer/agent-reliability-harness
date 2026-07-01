# Agent Reliability Benchmark Report

## Summary

| Metric | Value |
|---|---:|
| run_id | local-demo |
| scenarios_total | 2 |
| scenarios_passed | 2 |
| scenarios_failed | 0 |
| pass_rate | 1.0000 |

## Failure Type Counts

| failure_type | count |
|---|---:|
| none | 1 |
| policy_violation | 1 |

## Status Counts

| status | count |
|---|---:|
| blocked | 1 |
| passed | 1 |

## Scenario Results

| scenario_id | status | expected_failure | failure_type | passed | trace_file |
|---|---|---|---|---:|---|
| normal_agent_run | passed | none | none | True | runs/local-demo/local-demo/normal_agent_run/trace.jsonl |
| model_not_allowed | blocked | policy_violation | policy_violation | True | runs/local-demo/local-demo/model_not_allowed/trace.jsonl |

## Project Boundaries

- offline
- deterministic
- no real LLM API
- no real shell execution
- no real network calls
