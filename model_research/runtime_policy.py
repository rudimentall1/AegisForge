from dataclasses import asdict
from .schemas import RuntimeProfile


DEFAULT_PROFILES = {
    "researcher": RuntimeProfile(
        reasoning_effort="low",
        temperature=0.2,
        repetition_penalty=1.03,
    ),
    "analyst": RuntimeProfile(
        reasoning_effort="medium",
        temperature=0.15,
        repetition_penalty=1.05,
    ),
    "developer": RuntimeProfile(
        reasoning_effort="high",
        temperature=0.1,
        repetition_penalty=1.05,
    ),
    "security_checker": RuntimeProfile(
        reasoning_effort="high",
        temperature=0.1,
        repetition_penalty=1.05,
    ),
    "model_researcher": RuntimeProfile(
        reasoning_effort="high",
        temperature=0.1,
        repetition_penalty=1.05,
    ),
    "opportunity_hunter": RuntimeProfile(
        reasoning_effort="medium",
        temperature=0.25,
        repetition_penalty=1.05,
    ),
    "master": RuntimeProfile(
        reasoning_effort="high",
        temperature=0.1,
        repetition_penalty=1.05,
    ),
}


def get_profile(role: str) -> dict:
    profile = DEFAULT_PROFILES.get(role, RuntimeProfile())
    return asdict(profile)
