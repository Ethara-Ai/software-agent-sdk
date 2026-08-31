"""Register newer Anthropic models in LiteLLM's bundled model cost map.

The eval container runs behind a default-deny egress filter, so LiteLLM cannot
fetch model_prices_and_context_window.json from GitHub at import time and falls
back to the copy bundled in the wheel. Models newer than that copy are unknown,
and LiteLLM then refuses to send parameters it believes they do not support --
notably `thinking`, which it silently drops (drop_params) or rejects with
UnsupportedParamsError. The result is trajectories with no reasoning captured.

This runs at image build time and tops up the bundled map so the parameter
support check succeeds offline.
"""

import json
import pathlib
from importlib.resources import files

MODELS = (
    "claude-opus-4-8",
    "anthropic/claude-opus-4-8",
    "claude-opus-5",
    "anthropic/claude-opus-5",
)

path = pathlib.Path(
    str(files("litellm").joinpath("model_prices_and_context_window_backup.json"))
)
cost_map = json.loads(path.read_text(encoding="utf-8"))

# Pricing/shape is copied from the newest Opus entry that is present; the cost
# figures are cosmetic here (billing goes through the OAuth subscription bridge)
# and only exist to silence LiteLLM's "model isn't mapped yet" warning.
base = cost_map.get("claude-opus-4-5") or cost_map.get("claude-opus-4-1") or {}

entry = dict(base)
entry.update(
    {
        "litellm_provider": "anthropic",
        "mode": "chat",
        "supports_reasoning": True,
        "supports_function_calling": True,
        "supports_prompt_caching": True,
        "supports_tool_choice": True,
        "supports_vision": True,
        "max_input_tokens": 1_000_000,
        "max_output_tokens": 128_000,
        "max_tokens": 128_000,
    }
)

for name in MODELS:
    cost_map[name] = entry

path.write_text(json.dumps(cost_map), encoding="utf-8")
print(
    f"[litellm-model-map-patch] registered {', '.join(MODELS)} "
    f"({len(cost_map)} models)"
)
