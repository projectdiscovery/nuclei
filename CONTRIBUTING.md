# Contributing to ProjectDiscovery/Nuclei

We appreciate your interest in contributing to projectdiscovery/nuclei! This document provides clear guidelines for contributors.

## Getting Started

- Always base your work from the `dev` branch (this is the active development branch with the latest code).
- Before creating a Pull Request (PR), make sure there is a corresponding issue for your contribution. If there isn't one already, please create one first.
- Clearly describe the problem or improvement in the issue.

## Pull Requests

When creating a PR, please follow these guidelines:

- Link your PR to the corresponding issue.
- Provide clear context in the PR description to help reviewers understand the changes. The more information you provide, the faster the review process will be.
- Include an example of running the tool with the changed code, if applicable. Provide 'before' and 'after' examples when possible.
- Include steps for functional testing or how to reproduce the issue.
- If you're adding a new feature, make sure to include unit tests.

## Code Style

Please adhere to the existing coding style for consistency.

## Development

To ensure your changes work as expected and strictly adhere to the project's standards, please run the following commands before submitting a PR:

```sh
# Run tests
make test

# Run linters / vet
make vet

# Build the project
make build
```

## Questions

If you have any questions or need further guidance, feel free to ask in the issue or PR, or [reach out to the maintainers on Discord](https://discord.gg/projectdiscovery).

Thank you for your contribution!
