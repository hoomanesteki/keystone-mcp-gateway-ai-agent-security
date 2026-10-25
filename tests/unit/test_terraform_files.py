"""The AWS reference deployment (KS-905) carries no secret values and keeps the sandbox off."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TF_DIR = ROOT / "deploy" / "terraform" / "aws"
FILES = sorted([*TF_DIR.glob("*.tf"), *TF_DIR.glob("*.tfvars*")])

# A key whose name says it holds a secret, assigned a quoted string that is not a reference.
SECRET_ASSIGNMENT = re.compile(
    r"""^\s*(?P<key>[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|master[_-]?key)[A-Za-z0-9_-]*)
        \s*=\s*"(?P<value>[^"]*)"\s*$""",
    re.IGNORECASE | re.VERBOSE,
)
KNOWN_TOKEN_SHAPES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"postgres(?:ql)?(?:\+\w+)?://[^:/\s]+:[^@\s$]+@"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
]


def findings(name: str, text: str) -> list[str]:
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        code = line.split("#", 1)[0]
        match = SECRET_ASSIGNMENT.match(code)
        # An empty string, or one built only from references, holds no secret.
        if match and match["value"] and not re.fullmatch(r"(\$\{[^}]*\})+", match["value"]):
            found.append(f"{name}:{number}: {match['key']} is set to a literal")
        for shape in KNOWN_TOKEN_SHAPES:
            if shape.search(code):
                found.append(f"{name}:{number}: matches {shape.pattern}")
    return found


@pytest.mark.phase(9)
def test_no_hardcoded_secrets_in_tf() -> None:
    assert FILES, "deploy/terraform/aws holds no .tf files"

    problems = [p for path in FILES for p in findings(path.name, path.read_text())]

    assert problems == []


@pytest.mark.phase(9)
def test_the_secret_check_catches_a_literal() -> None:
    bad = 'password = "hunter2hunter2"\nmaster_key = "abc"\nurl = "postgresql://u:pw@host/db"\n'
    good = 'password = random_password.db.result\nsecret_string = each.value\npassword = ""\n'

    assert len(findings("bad.tf", bad)) == 3
    assert findings("good.tf", good) == []


@pytest.mark.phase(9)
def test_the_sandbox_is_off_on_fargate_and_the_secrets_come_from_secrets_manager() -> None:
    ecs = (TF_DIR / "ecs.tf").read_text()

    assert re.search(r'KEYSTONE_SANDBOX_ENABLED\s*=\s*"false"', ecs)
    for name in ("DATABASE_URL", "MASTER_KEYS", "REDIS_URL"):
        assert f"KEYSTONE_{name}" in ecs
    assert "aws_secretsmanager_secret.keystone" in ecs
    assert "valueFrom" in ecs


@pytest.mark.phase(9)
def test_the_task_env_follows_the_certificate() -> None:
    # Keystone in prod refuses http addresses. Without a certificate the ALB serves http, so the
    # task must not claim prod, and with one an http URL has to fail the plan, not the startup.
    alb = (TF_DIR / "alb.tf").read_text()
    ecs = (TF_DIR / "ecs.tf").read_text()

    assert re.search(r'https\s*=\s*var\.acm_certificate_arn != ""', alb)
    assert re.search(r'KEYSTONE_ENV\s*=\s*local\.https \? "prod" : "dev"', ecs)
    assert not re.search(r'KEYSTONE_ENV\s*=\s*"prod"', ecs)
    # Dev mode on the task keeps the audit log closed, as prod does.
    assert re.search(r'KEYSTONE_AUDIT__FAIL_CLOSED\s*=\s*"true"', ecs)
    preconditions = re.findall(r"precondition \{(.*?)\}", ecs, re.DOTALL)
    assert any('startswith(var.public_base_url, "https://")' in p for p in preconditions)
    assert any('startswith(var.oidc_issuer, "https://")' in p for p in preconditions)
    assert all("!local.https ||" in p for p in preconditions)


@pytest.mark.phase(9)
def test_the_stack_has_the_planned_pieces() -> None:
    text = "\n".join(path.read_text() for path in TF_DIR.glob("*.tf"))

    for resource in (
        "aws_vpc",
        "aws_lb",
        "aws_ecs_service",
        "aws_db_instance",
        "aws_elasticache_replication_group",
        "aws_cloudwatch_log_group",
        "aws_cognito_user_pool",
    ):
        assert f'resource "{resource}"' in text
    assert '"db.t4g.micro"' in text
    assert '"cache.t4g.micro"' in text
    assert "acm_certificate_arn" in text
    assert "enable_cognito" in text
    assert "enable_adot" in text
