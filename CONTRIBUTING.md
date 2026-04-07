# Contributing to Vargate

Thank you for considering contributing to Vargate! This document explains
how to get involved.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run the tests (see below)
6. Commit with a clear message
7. Push to your fork and open a Pull Request

## Development Setup

```bash
# Clone and start all services
git clone https://github.com/vargate/vargate-proxy.git
cd vargate-proxy
docker compose up --build

# Run the test suite (in a separate terminal)
pip install requests
python test_demo.py
python test_hotswap.py
python test_behavioral.pypython test_replay.py
python test_crypto_shredding.py
python test_blockchain.py
```

## Branch Naming

- `feature/` — new functionality
- `fix/` — bug fixes
- `docs/` — documentation only
- `refactor/` — code restructuring with no behaviour change

## Commit Messages

Use clear, imperative-mood commit messages:

- `Fix /anchor/verify 500 when no records exist`
- `Add per-tenant rate limiting middleware`
- `Update README with known limitations`

## Code Style

- **Python**: Follow PEP 8. Use type hints where practical.
- **JavaScript/React**: Use consistent formatting (Prettier defaults).
- **Rego**: Follow OPA style conventions. Keep rules composable and testable.

## Pull Request Process

1. Ensure all existing tests pass
2. Add tests for new functionality
3. Update documentation if you change public APIs or behaviour
4. Keep PRs focused — one logical change per PR
5. Reference any related issues in the PR description
## What We're Looking For

- Bug fixes and test coverage improvements
- Documentation improvements
- New OPA policy templates
- Dashboard enhancements
- Performance improvements (especially gateway latency)
- Integration examples and code snippets

## Security Issues

If you discover a security vulnerability, please do **not** open a public
issue. Instead, email security@vargate.ai with details. We will respond
within 48 hours.

## Questions?

Open a GitHub Discussion or reach out to the maintainers.
