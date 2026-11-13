DETERMINISTIC_EVALUATOR = "deterministic_policy"

ALLOWED_VERDICT_EVALUATORS = frozenset({DETERMINISTIC_EVALUATOR})


def assert_verdict_evaluator(evaluator: str) -> None:
    if evaluator not in ALLOWED_VERDICT_EVALUATORS:
        raise ValueError(
            "An LLM cannot be the final security authority. "
            f"Evaluator must be {DETERMINISTIC_EVALUATOR}."
        )
