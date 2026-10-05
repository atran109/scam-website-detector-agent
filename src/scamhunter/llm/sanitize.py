"""Wrap untrusted page content in delimited data blocks for prompts."""

import hashlib
import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")


def untrusted(label: str, text: str, max_chars: int) -> str:
    """Page-derived text as an inert data block.

    - control and bidi/zero-width characters stripped (hidden-instruction tricks),
    - truncated with an explicit marker (no silent cut),
    - the delimiter carries a nonce derived from the content, so a page can't close the block
      by writing the tag itself; deterministic so identical inputs still hit the LLM cache.
    """
    clean = _CONTROL.sub("", text)
    truncated = len(clean) > max_chars
    clean = clean[:max_chars]
    nonce = hashlib.sha256(clean.encode()).hexdigest()[:12]
    tag = f"untrusted_{label}_{nonce}"
    clean = clean.replace(tag, "[removed]")
    note = f"\n[truncated: {len(text) - max_chars} more characters not shown]" if truncated else ""
    return f"<{tag}>\n{clean}{note}\n</{tag}>"
