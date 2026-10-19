"""Normalizer.

The project guide's "Input normalizer" step describes how untrusted input
should be tamed before it is compared, classified or logged, so that an
attacker cannot smuggle a payload past signature or AI checks by hiding it
behind encoding tricks:

- URL-decode (percent-encoded ``%XX`` sequences) so that ``%61%73%73%65%72%74``
  becomes ``assault``.
- Lowercase the result, so that ``Admin`` and ``ADMIN`` are indistinguishable
  from ``admin``.

The normalized value is what the threat signatures, the AI classifier and the
audit log all see, so the normalization has to be deterministic and
losslessly apply to every field the sentinel captures.
"""

from __future__ import annotations

from typing import Any


def normalize(value: Any) -> Any:
    """Normalize one input value the same way every time.

    ``None`` and non-string values pass through untouched so the normalizer is
    safe to apply to a dict of headers, query parameters, path parts and so on.
    """
    if value is None or not isinstance(value, str):
        return value
    return normalize_string(value)


def normalize_string(value: str) -> str:
    """URL-decode and lowercase a single string input.

    Only the percent-encoded ``%XX`` sequences are decoded; anything that is
    already valid UTF-8 passes through unchanged.  This keeps the behaviour
    predictable on badly-formed input instead of throwing away the rest of the
    request.
    """
    decoded = _url_decode(value)
    return decoded.lower()


def _url_decode(value: str) -> str:
    """Decode ``%XX`` percent escapes and ``+`` as space once."""
    try:
        from urllib.parse import unquote

        return unquote(value, errors="replace")
    except Exception:  # pragma: no cover - defensive fallback
        return value
