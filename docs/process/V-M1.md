# V-M1 — minor inspection-boundary violation

**Date:** 2026-11-16

During an early local inspection, a broad workflow-file glob read two
phaseC workflow files by mistake. This was a read-only inspection mistake.
No content from those files is reproduced, summarized, quoted, or used in any
report, comparison, test, or finding. No isolated target was entered into any
comparison.

The corrective rule is now explicit: every future workflow/repository glob must
exclude both `phasec` and `seal` paths, for example:

```text
find .github/workflows -type f ! -path '*/phasec*' ! -path '*/seal*' -print
```

The exclusion applies before any read, search, copy, diff, or generated report.
No phaseC or seal path is an allowed input to this workstream.
