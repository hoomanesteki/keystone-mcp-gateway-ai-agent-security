"""The three configs of the red team and what the gateway must say of itself for each (KS-902).

C0 is `KEYSTONE_PROFILE=passthrough`, C1 has the access rules and the approvals without the Rule of
Two and without the scanner, and C2 is everything. The runner checks a gateway against this table
before it writes a line, and the report reads the same table to say what a config had in force.
"""

from __future__ import annotations

from typing import Literal

Config = Literal["C0", "C1", "C2"]
CONFIGS: tuple[Config, ...] = ("C0", "C1", "C2")
CONFIG_NAMES: dict[str, str] = {
    "C0": "C0 passthrough",
    "C1": "C1 policy and approvals",
    "C2": "C2 full",
}

# The policies of the Rule of Two (policies/default). C2 has them and C1 does not.
RULE_OF_TWO = frozenset({"rule-of-two", "tainted-external-effect", "deny-critical-when-tainted"})
# What the gateway must say of itself for each label: the profile, whether it scans, and whether
# the policies of the Rule of Two are in force (None: not looked at).
EXPECTED: dict[Config, tuple[str, str, bool | None]] = {
    "C0": ("passthrough", "off", None),
    "C1": ("full", "off", False),
    "C2": ("full", "on", True),
}
