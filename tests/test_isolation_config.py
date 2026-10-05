"""Static checks on the sandbox configuration and the code-level guard (no Docker needed)."""

import json
import re
import tomllib

import pytest
import yaml

from scamhunter.config import REPO_ROOT, SandboxError, load_settings, require_egress_proxy

SQUID_CONF = (REPO_ROOT / "docker/egress-proxy/squid.conf").read_text()
COMPOSE = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())

REQUIRED_DENIED = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


@pytest.mark.parametrize("cidr", REQUIRED_DENIED)
def test_squid_denies_range(cidr: str) -> None:
    assert re.search(rf"^acl blocked_dst dst {re.escape(cidr)}\b", SQUID_CONF, re.M)


def test_squid_rule_order() -> None:
    rules = re.findall(r"^http_access (.+)$", SQUID_CONF, re.M)
    assert rules.index("deny blocked_dst") < rules.index("allow crawler_net")
    assert rules[-1] == "deny all"


def test_crawler_only_on_internal_network() -> None:
    assert COMPOSE["networks"]["internal"]["internal"] is True
    assert COMPOSE["services"]["crawler"]["networks"] == ["internal"]


@pytest.mark.parametrize("service", ["crawler", "egress-proxy"])
def test_service_hardening(service: str) -> None:
    svc = COMPOSE["services"][service]
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["mem_limit"] and svc["pids_limit"]
    assert "privileged" not in svc and "ports" not in svc


def test_crawler_mounts_only_runs_and_output() -> None:
    mounts = COMPOSE["services"]["crawler"]["volumes"]
    assert sorted(m.split(":")[1] for m in mounts) == ["/app/output", "/app/runs"]


def test_seccomp_profile_allows_userns_syscalls() -> None:
    profile = json.loads((REPO_ROOT / "docker/seccomp/chromium.json").read_text())
    unconditional = [s for s in profile["syscalls"] if not s.get("includes") and not s.get("args")]
    allowed = {n for s in unconditional if s["action"] == "SCMP_ACT_ALLOW" for n in s["names"]}
    # clone/unshare/setns from Playwright's profile; chroot made unconditional by us so the
    # sandbox works under cap_drop ALL (the kernel still checks CAP_SYS_CHROOT per namespace).
    assert {"clone", "unshare", "setns", "chroot"} <= allowed
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"


def test_playwright_version_matches_dockerfile() -> None:
    deps = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    pinned = next(d.split("==")[1] for d in deps if d.startswith("playwright=="))
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    assert f"ARG PLAYWRIGHT_VERSION={pinned}" in dockerfile


def test_no_sandbox_never_disabled_in_code() -> None:
    sources = "\n".join(p.read_text() for p in (REPO_ROOT / "src").rglob("*.py"))
    assert "chromium_sandbox=True" in sources
    for flag in ('"--no-sandbox"', "--disable-web-security", "accept_downloads=True"):
        assert flag not in sources


def test_settings_load() -> None:
    settings = load_settings()
    assert settings.triage.concurrency > 0
    assert settings.classify.scam_threshold == 0.45


def test_require_egress_proxy_refuses_outside_container(monkeypatch) -> None:
    monkeypatch.delenv("EGRESS_PROXY", raising=False)
    with pytest.raises(SandboxError):
        require_egress_proxy()
    monkeypatch.setenv("EGRESS_PROXY", "http://egress-proxy:3128")
    with pytest.raises(SandboxError):  # still no /.dockerenv on the host
        require_egress_proxy()


def test_settings_match_design() -> None:
    """config/settings.yaml must equal the block in DESIGN §3.5 (drift guard: a feature flag
    flipped only in the doc once silently disabled Wayback recovery)."""
    design = (REPO_ROOT / "docs" / "DESIGN.md").read_text()
    section = design[design.index("**`config/settings.yaml`**") :]
    block = re.search(r"```yaml\n(.*?)```", section, re.S).group(1)
    assert yaml.safe_load(block) == yaml.safe_load((REPO_ROOT / "config/settings.yaml").read_text())
