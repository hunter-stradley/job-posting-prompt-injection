# Benchmark results

Static detector vs the synthetic labeled benchmark (`dataset.json`). Regenerate with `python3 benchmark/run_benchmark.py`.

## Detection (malicious vs benign, REVIEW threshold)

- **Precision:** 1.000
- **Recall:** 1.000
- **F1:** 1.000
- Confusion: TP=17 FP=0 FN=0 TN=1 (n=18)
- **Label exactness:** 1.000 (classify() assigns exactly the expected label, incl. the deliberately-unlabeled cases)

## Per-case

| id | vector | malicious | expected | label | score | detected | label_exact |
|----|--------|-----------|----------|-------|------:|:--------:|:-----------:|
| white | css_white_on_white | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| displaynone | display_none | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| tiny | font_size_zero | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| offscreen | offscreen | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| hiddenform | hidden_form_field | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| jsonld | json_ld_keyword | True | CONFIRMED | CONFIRMED | 90 | ✓ | ✓ |
| jsonld_semantic | json_ld_semantic | True | CONFIRMED | CONFIRMED | 90 | ✓ | ✓ |
| tagblock | unicode_tag_block | True | CONFIRMED | CONFIRMED | 80 | ✓ | ✓ |
| varselector | variation_selector | True | CONFIRMED | CONFIRMED | 80 | ✓ | ✓ |
| sronly_evil | sr_only_instruction | True | CONFIRMED | CONFIRMED | 95 | ✓ | ✓ |
| homoglyph | homoglyph | True | REVIEW | REVIEW | 55 | ✓ | ✓ |
| greek_homoglyph | homoglyph | True | REVIEW | REVIEW | 55 | ✓ | ✓ |
| attr | attribute_injection | True | None | None | 45 | ✓ | ✓ |
| comment | html_comment | True | None | None | 80 | ✓ | ✓ |
| datastar | data_attribute | True | None | None | 45 | ✓ | ✓ |
| bidi | bidi_control | True | None | None | 80 | ✓ | ✓ |
| zerowidth | zero_width | True | None | None | 45 | ✓ | ✓ |
| sronly_benign | benign_accessibility | False | None | None | 5 | · | ✓ |

**Reading the table:** cases with `expected = null` are real injection vectors the high-precision `classify()` intentionally does **not** auto-label (e.g. bare HTML comments, attribute injection, zero-width) to avoid false positives. They are still *detected* — they cross the score threshold (`detected = ✓`) — so they count as detection true-positives while remaining unlabeled. That separation between *detection* and *auto-labeling* is the precision/recall trade-off made explicit; the benchmark pins both so a refactor can't quietly shift it.

