"""logmine plugin — exact, local log-file intelligence.

Registers three read-only tools (``log_summarize``, ``log_grep``, ``log_timeline``).
Pure standard library: no network, no credentials, no background work, no self-update.
"""

from __future__ import annotations

from . import logmine as _lm


def register(ctx) -> None:
    """Called once by the plugin loader; register the three read-only log tools."""
    ctx.register_tool(name="log_summarize", toolset="logmine",
                      schema=_lm.LOG_SUMMARIZE, handler=_lm.log_summarize)
    ctx.register_tool(name="log_grep", toolset="logmine",
                      schema=_lm.LOG_GREP, handler=_lm.log_grep)
    ctx.register_tool(name="log_timeline", toolset="logmine",
                      schema=_lm.LOG_TIMELINE, handler=_lm.log_timeline)
