# Contributing to NextSploit

Thank you for your interest in contributing to NextSploit! NextSploit is a dedicated security auditing framework and intelligence platform for Next.js applications.

## How Can You Contribute?

1. **Submit YAML Detection Rules**: Add new vulnerability detection rules to `knowledge/rules/core/packs/nextjs/`.
2. **Report Bugs**: Open an issue detailing steps to reproduce.
3. **Enhance Documentation**: Improve guides or generate updated detection docs via `python nextsploit.py docs generate`.
4. **Develop Plugins**: Author Python plugins in `plugins/` for complex AST or multi-stage analysis.

## Development Workflow

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the test suite:
   ```bash
   python -m pytest tests/ -v
   ```
4. Validate your YAML rule changes:
   ```bash
   python nextsploit.py docs validate
   ```
5. Ensure all test cases pass before opening a Pull Request.

## Rule Authoring Standards
Please read the [Rule Author Guide](docs/RULE_AUTHOR_GUIDE.md) before submitting detection rules.
