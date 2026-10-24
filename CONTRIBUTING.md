# Contributing

1. Use Python 3.11+ and a virtual environment.
2. Install `requirements-dev.txt`.
3. Keep parser code independent of live capture permissions.
4. Add meaningful fixtures for detector changes, including a normal counterexample.
5. Preserve capture-time semantics and per-session rule snapshots.
6. Run `python -m pytest -q` and `python scripts/evaluate.py`.
7. Update README/SRS when a user-visible behavior or limitation changes.

Use synthetic traffic or datasets with an appropriate license. Never commit real credentials, private traffic captures, or the `instance/` directory. UI changes should be checked at desktop and phone widths and with reduced motion enabled.

A contribution should explain the concrete change, why it is useful, how it was verified, and any known limitations.
