# Contributing

## Coding standards (agent PR checklist)

- Type hints on public functions and dataclasses for structured data.
- Docstrings (what/why), clear names, small functions (prefer <50 lines).
- Handle errors gracefully; log context, no bare `except:`; never print secrets.
- Use `logging`, not `print`; no global state; pure functions where possible.
- Security: never commit secrets; use env/CI secrets; validate inputs; least privilege.
- Tests for new logic (unit or smoke) and update existing ones when behavior changes.
- Formatting & lint: Black (88), Flake8 (E/W, ignore E203/W503); keep imports tidy.
- Human PR: title with prefix (`feat:`, `fix:`, `chore:`), short description, test notes.
