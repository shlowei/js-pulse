# Contributing to js-pulse

Two ways to contribute, in order of how much I appreciate them:

1. **Open a PR with a new detection pattern.** Highest leverage. Every bug bounty hunter has a pattern in their notes app that the rest of us would benefit from.
2. **Open an issue with a false positive** you hit. Include the JS snippet (sanitized) and what made it a false positive. I tune the score weights from these.

For everything else (refactors, new features, docs): open an issue first so we can talk about it before you spend a weekend on it.

## Adding a detection pattern

The pattern format is intentionally simple. It's just Python regex with metadata, not a DSL.

**To add a secret pattern** — edit `core/analyzers/secret_scanner.py` and add an entry to the `PATTERNS` list:

```python
("sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", Severity.CRITICAL),
```

Format: `(regex, human-readable-name, severity)`.

**To add a vulnerability pattern** — edit `core/analyzers/vuln_pattern.py` and add to `PATTERNS`:

```python
(
    r"\beval\s*\(",
    "eval() call",
    "Dynamic code execution. If the argument is user-controllable, this is RCE.",
    Severity.HIGH,
),
```

Format: `(regex, title, description, severity)`.

Then add a test case to `tests/test_analyzers.py`.

## Coding style

- Python 3.8+ compatible (we use `from __future__ import annotations` if needed for forward refs)
- Type hints where it makes the code clearer
- Comments explain *why*, not *what*
- One line of code per logical concept, when possible
- No external dependencies. If you need a new dep, the answer is "find a way to do it with stdlib"

## Reporting issues

If you hit a false positive, please include:

- The pattern that fired (printed in the finding's `detector` field)
- The JS snippet (sanitized — redact any actual keys, emails, etc.)
- What made it a false positive (e.g. "this is a test fixture", "this is in a comment", "this is a public doc URL")

If you're reporting a missed detection (false negative), include:

- A description of what you expected js-pulse to catch
- A redacted example if you have one

## License

By contributing, you agree that your contributions will be licensed under the MIT License.