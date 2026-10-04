"""Load settings.yaml + env into typed Settings."""

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

# The checkout root locally; set to /app in the container, where the package lives in site-packages.
REPO_ROOT = Path(os.environ.get("SCAMHUNTER_HOME") or Path(__file__).resolve().parents[2])
DEFAULT_SETTINGS_PATH = REPO_ROOT / "config" / "settings.yaml"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a typo in settings.yaml fails loudly


class RunSettings(_Section):
    concurrency: int
    site_timeout_s: int
    resume: bool


class BrowserSettings(_Section):
    viewport_desktop: tuple[int, int]
    viewport_mobile: tuple[int, int]
    mobile_hint_patterns: list[str]
    navigation_timeout_ms: int
    block_downloads: bool
    element_provider: Literal["playwright", "stagehand"]
    tracing: Literal["off", "on_scam_or_failure", "always"]


class AgentSettings(_Section):
    enabled: bool
    max_steps: int
    max_seconds: int
    max_consecutive_failures: int
    trigger: str
    target_assets: list[str]


class TriageSettings(_Section):
    concurrency: int
    timeout_s: float
    max_body_bytes: int
    max_redirects: int
    retries: int


class HttpSettings(_Section):
    chrome_major_version: int
    accept_language: str


class LLMSettings(_Section):
    judge_model: str
    navigator_model: str
    helper_model: str
    temperature: float
    cache_responses: bool


class ClassifySettings(_Section):
    uncertain_band: tuple[float, float]
    scam_threshold: float


class FeatureSettings(_Section):
    wallet_mock: bool
    qr_decode: bool
    ocr: bool
    archive_fallback: bool


class IdentitySettings(_Section):
    email_provider: str
    on_email_rejected: str


class EvalSettings(_Section):
    min_labels: int
    label_source: str


class Settings(_Section):
    run: RunSettings
    browser: BrowserSettings
    agent: AgentSettings
    triage: TriageSettings
    http: HttpSettings
    llm: LLMSettings
    classify: ClassifySettings
    features: FeatureSettings
    identity: IdentitySettings
    eval: EvalSettings


def load_settings(path: Path = DEFAULT_SETTINGS_PATH) -> Settings:
    return Settings.model_validate(yaml.safe_load(path.read_text()))


class SandboxError(RuntimeError):
    """Raised when code that contacts real sites runs outside the sandbox."""


def require_egress_proxy() -> str:
    """Return the egress proxy URL, refusing to run outside the crawler container.

    Enforces the hard rule "never visit a real target site outside the Docker container":
    every code path that contacts a target site calls this first.
    """
    proxy = os.environ.get("EGRESS_PROXY")
    if not proxy or not Path("/.dockerenv").exists():
        raise SandboxError(
            "Refusing to contact target sites: not inside the crawler container "
            "(EGRESS_PROXY unset or /.dockerenv missing). Use `make triage` / `make run`."
        )
    return proxy
