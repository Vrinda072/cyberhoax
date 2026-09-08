"""
attacks/ — attack payloads for the harness.

Each attack is an `Attack`: a legitimate-looking user message plus, optionally,
poisoned tool data (`webpages` / `docs`) that `run_agent` will merge in so the
agent encounters the payload the way it would in production.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Attack:
    attack_id: str
    category: str  # direct | indirect | tool_misuse | exfiltration | benign
    user_message: str
    description: str = ""
    # Extra tool data merged into the agent's stores for this run.
    webpages: dict[str, str] = field(default_factory=dict)
    docs: dict[str, str] = field(default_factory=dict)


# Imported at the bottom so attacks.* can do `from attacks import Attack`.
from attacks.direct import DIRECT_ATTACKS  # noqa: E402
from attacks.indirect import INDIRECT_ATTACKS  # noqa: E402
from attacks.tool_misuse import TOOL_MISUSE_ATTACKS  # noqa: E402
from attacks.exfiltration import EXFILTRATION_ATTACKS  # noqa: E402

# The 8-attack suite, in a stable order.
ALL_ATTACKS = [
    *DIRECT_ATTACKS,
    *INDIRECT_ATTACKS,
    *TOOL_MISUSE_ATTACKS,
    *EXFILTRATION_ATTACKS,
]
