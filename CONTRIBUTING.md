# Contributing to owlzops-mapper

## 🤖 AI-Assisted Development Policy

owlzops-mapper is openly developed with AI assistance (Claude, Copilot, etc.)
as part of our workflow. We believe AI tools are legitimate accelerators
for quality source-available software.

**What we require from ALL contributions (human or AI-assisted):**
- ✅ Contributor understands every line they submit
- ✅ Code is tested and tests pass locally (`cargo test`)
- ✅ Clippy is clean (`cargo clippy -- -D warnings`)
- ✅ Formatted (`cargo fmt`)
- ✅ Security implications are considered
- ✅ Contributor can explain their changes in review

**What we do NOT accept:**
- ❌ Blind copy-paste from AI without understanding
- ❌ AI-generated code that hasn't been reviewed by the author
- ❌ Fabricated benchmarks or test results

Tools don't define quality. Code review does.

## Getting Started

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run `cargo test && cargo clippy && cargo fmt`
5. Open a PR against `develop`

## Branch Naming

- `feature/description` — new functionality
- `fix/description` — bug fixes
- `docs/description` — documentation only
- `release/v0.x.0` — release preparation

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

## 🐛 Reporting Bugs

If you find a bug in `owlzops-mapper`, please open an issue in the repository. To help us fix it faster, include the following:

* **Environment:** Your OS and Rust version (`rustc --version`).
* **Steps to reproduce:** Exactly what you did before it broke.
* **Expected behavior:** What you thought would happen vs what actually happened.