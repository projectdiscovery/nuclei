# Issue Template References

## Overview

This folder contains the preserved issue templates that are **not** directly accessible to users. These templates serve as references for maintainers when converting discussions to issues.

## New Workflow

### For Users:
1. **All reports start in Discussions** - Users cannot create issues directly
2. Bug reports go to [Q&A Discussions](https://github.com/projectdiscovery/nuclei/discussions/categories/q-a)
3. Feature requests go to [Ideas Discussions](https://github.com/projectdiscovery/nuclei/discussions/categories/ideas)
4. This helps filter out duplicate questions, invalid reports, and ensures proper triage

### For Maintainers:
1. **Review discussions** in both Q&A and Ideas categories
2. **Validate the reports** - ensure they're actual bugs/valid feature requests
3. **Use reference templates** when converting discussions to issues:
   - Copy content from `bug-report-reference.yml` or `feature-request-reference.yml`
   - Create a new issue manually with the appropriate template structure
   - Link back to the original discussion
   - Close the discussion or mark it as resolved

## Benefits

- **Better triage**: Avoid cluttering issues with questions and invalid reports
- **Community involvement**: Discussions allow for community input before creating issues
- **Quality control**: Maintainers can ensure issues follow proper format and contain necessary information
- **Reduced noise**: Only validated, actionable items become issues

## Reference Templates

- `bug-report-reference.yml` - Use when converting bug reports from discussions to issues
- `feature-request-reference.yml` - Use when converting feature requests from discussions to issues

## Converting a Discussion to Issue

1. Identify a valid discussion that needs to become an issue
2. Go to the main repository's Issues tab
3. Click "New Issue"
4. Manually create the issue using the reference template structure
5. Include all relevant information from the discussion
6. Add a comment linking back to the original discussion
7. Apply appropriate labels
8. Close or mark the discussion as resolved with a link to the created issue
