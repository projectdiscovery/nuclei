# Nuclei Discussion Guidelines

## Before Creating a Discussion

1. **Search existing discussions and issues** to avoid duplicates
2. **Check the documentation** and README first
3. **Browse the FAQ** and common questions

## Bug Reports in Discussions

When reporting a bug in [Q&A Discussions](https://github.com/projectdiscovery/nuclei/discussions/categories/q-a), please include:

### Required Information:
- **Clear title** with `[BUG]` prefix (e.g., "[BUG] Nuclei crashes when...")
- **Current behavior** - What's happening now?
- **Expected behavior** - What should happen instead?
- **Steps to reproduce** - Commands or actions that trigger the issue
- **Environment details**:
  - OS and version
  - Nuclei version (`nuclei -version`)
  - Go version (if installed via `go install`)
- **Log output** - Run with `-verbose` or `-debug` for detailed logs
- **Redact sensitive information** - Remove target URLs, credentials, etc.

### After Discussion:
- Maintainers will review and validate the bug report
- Valid bugs will be converted to issues with proper labels and tracking
- Questions and misconfigurations will be resolved in the discussion

## Feature Requests in Discussions

When requesting a feature in [Ideas Discussions](https://github.com/projectdiscovery/nuclei/discussions/categories/ideas), please include:

### Required Information:
- **Clear title** with `[FEATURE]` prefix (e.g., "[FEATURE] Add support for...")
- **Feature description** - What do you want to be added?
- **Use case** - Why is this feature needed? What problem does it solve?
- **Implementation ideas** - If you have suggestions on how it could work
- **Alternatives considered** - What other solutions have you thought about?

### After Discussion:
- Community and maintainers will discuss the feasibility
- Popular and viable features will be converted to issues
- Similar features may be grouped together
- Rejected features will be explained in the discussion

## Getting Help

For general questions, troubleshooting, and "how-to" topics:
- Use [Q&A Discussions](https://github.com/projectdiscovery/nuclei/discussions/categories/q-a)
- Join the [Discord server](https://discord.gg/projectdiscovery) #nuclei channel
- Check existing discussions for similar questions

## Discussion to Issue Conversion Process

Only maintainers can convert discussions to issues. The process:

1. **Validation** - Maintainers review the discussion for completeness and validity
2. **Classification** - Determine if it's a bug, feature, enhancement, etc.
3. **Issue creation** - Create a properly formatted issue with appropriate labels
4. **Linking** - Link the issue back to the original discussion
5. **Resolution** - Mark the discussion as resolved or close it

This process ensures:
- High-quality issues that are actionable
- Proper triage and labeling
- Reduced noise in the issue tracker
- Community involvement in the validation process

## Why This Process?

- **Better organization** - Issues contain only validated, actionable items
- **Community input** - Discussions allow for community feedback before escalation
- **Quality control** - Maintainers ensure proper formatting and information
- **Reduced maintenance** - Fewer invalid or duplicate issues to manage
- **Clear separation** - Questions vs. actual bugs/features are clearly distinguished
