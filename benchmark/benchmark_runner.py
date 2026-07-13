"""
BenchmarkRunner for AgentReliabilityHarness.

Batch-runs all scenarios through run_scenario_day5 (offline mock) or
run_scenario_live (real API + sandbox), collects results, and produces
a scorecard via ScorecardGenerator.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from benchmark.runner import run_scenario_day5, run_scenario_live
from benchmark.scorecard import ScorecardGenerator
from benchmark.spec import ScenarioSpec, load_scenarios


@dataclass
class BenchmarkRunResult:
    """Result of a full benchmark run across all scenarios.

    Attributes:
        run_id: Unique identifier for this benchmark run.
        scenarios_total: Number of scenarios loaded.
        scenarios_passed: Number of scenarios where passed == True.
        scenarios_failed: Number of scenarios where passed != True.
        pass_rate: Fraction of passed scenarios (0.0 – 1.0).
        results: Per-scenario result dicts from run_scenario_day5.
        output_dir: Root output directory for this run.
        scorecard_file: Path to the generated scorecard.json, if any.
    """

    run_id: str
    scenarios_total: int
    scenarios_passed: int
    scenarios_failed: int
    pass_rate: float
    results: list[dict[str, Any]] = field(default_factory=list)
    output_dir: str = ""
    scorecard_file: str | None = None


class BenchmarkRunner:
    """Load and execute all scenarios, then generate a scorecard.

    Usage::

        runner = BenchmarkRunner("benchmark/scenarios", "runs/output")
        result = runner.run()
        print(result.pass_rate)

    Args:
        scenarios_dir: Directory containing scenario YAML files.
        output_dir: Root directory for trace and scorecard output.
        run_id: Optional fixed run identifier (auto-generated if None).
        live: If True, use run_scenario_live instead of run_scenario_day5.
        provider_override: Override provider for all scenarios.
        model_override: Override model for all scenarios.
        tool_executor_override: Override tool executor for all scenarios.
        sandbox_root: Override sandbox root for local_sandbox executor.
    """

    def __init__(
        self,
        scenarios_dir: str | Path,
        output_dir: str | Path,
        run_id: str | None = None,
        live: bool = False,
        provider_override: str | None = None,
        model_override: str | None = None,
        tool_executor_override: str | None = None,
        sandbox_root: str | None = None,
    ) -> None:
        self._scenarios_dir = Path(scenarios_dir)
        self._output_dir = Path(output_dir)
        self._run_id = run_id or uuid.uuid4().hex[:12]
        self._live = live
        self._provider_override = provider_override
        self._model_override = model_override
        self._tool_executor_override = tool_executor_override
        self._sandbox_root = sandbox_root

    @property
    def run_id(self) -> str:
        """The run identifier for this benchmark."""
        return self._run_id

    def _apply_overrides(self, scenario: ScenarioSpec) -> ScenarioSpec:
        """Apply CLI overrides to a scenario without mutating the original."""
        if not any([
            self._provider_override,
            self._model_override,
            self._tool_executor_override,
        ]):
            return scenario

        agent_run_data = scenario.agent_run.model_dump()
        if self._provider_override:
            agent_run_data["provider"] = self._provider_override
        if self._model_override:
            agent_run_data["model"] = self._model_override
        if self._tool_executor_override:
            agent_run_data["tool_executor"] = self._tool_executor_override

        from benchmark.spec import AgentRunSpec
        new_agent_run = AgentRunSpec(**agent_run_data)

        scenario_data = scenario.model_dump()
        scenario_data["agent_run"] = new_agent_run.model_dump()
        return ScenarioSpec(**scenario_data)

    def run(self) -> BenchmarkRunResult:
        """Execute all scenarios and produce a scorecard.

        Each scenario is run independently; an exception in one scenario
        is recorded as a failed result and does not abort the benchmark.

        Returns:
            BenchmarkRunResult with aggregated statistics and per-scenario
            results.
        """
        scenarios = load_scenarios(self._scenarios_dir)
        run_output = self._output_dir / self._run_id
        results: list[dict[str, Any]] = []

        for scenario in scenarios:
            scenario = self._apply_overrides(scenario)
            try:
                if self._live:
                    result = run_scenario_live(
                        scenario,
                        output_dir=run_output,
                        sandbox_root=self._sandbox_root,
                    )
                else:
                    result = run_scenario_day5(scenario, output_dir=run_output)
            except Exception as exc:
                # Record the exception as a failed result without aborting
                result = {
                    "scenario_id": scenario.id,
                    "status": "error",
                    "expected_failure": scenario.expected_failure.value,
                    "failure_type": "error",
                    "passed": False,
                    "trace_file": None,
                    "events_count": 0,
                    "error": str(exc),
                }
            results.append(result)

        # Generate scorecard
        gen = ScorecardGenerator()
        scorecard = gen.generate(results, self._run_id, run_output)
        scorecard_path = run_output / "scorecard.json"
        gen.write_json(scorecard, scorecard_path)

        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed
        pass_rate = passed / total if total > 0 else 0.0

        return BenchmarkRunResult(
            run_id=self._run_id,
            scenarios_total=total,
            scenarios_passed=passed,
            scenarios_failed=failed,
            pass_rate=pass_rate,
            results=results,
            output_dir=str(run_output),
            scorecard_file=str(scorecard_path),
        )
