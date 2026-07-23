# Corpus Schema

CAIRN uses SQLite by default at `data/cairn.sqlite`.

## samples

One row per SHA256. This table deduplicates the corpus by exact file hash.

- `sha256`
- `name`
- `vt_url`
- `first_seen`
- `last_seen`
- `file_type`
- `detections`
- `tags_json`
- `raw_json`
- `collected_at`
- `updated_at`

## acquisition_runs

One row per manual filter run.

- `filter_slug`
- `filter_name`
- `query_text`
- `effective_query_text`
- `fallback_reason`
- `status`
- `requested`
- `found`
- `imported`
- `matched_samples`
- `rule_hits`
- `started_at`
- `completed_at`

## sample_filters

Many-to-many provenance between samples and acquisition filters.

- `sample_sha256`
- `filter_slug`
- `filter_name`
- `acquisition_run_id`
- `first_imported_at`
- `last_imported_at`
- `times_seen`

## rule_matches

Current local rule matches per sample and rule.

- `sample_sha256`
- `rule_name`
- `tier`
- `artifact_type`
- `artifact_class`
- `confidence`
- `description`
- `matched_strings_json`
- `matched_at`

## known_seeds

Known sample anchors used to calibrate rules. Hashes identify exact seed samples; they do not generalize to variants.

- `sha256`
- `family_name`
- `source_name`
- `source_url`
- `description`
- `notes`
- `labels_json`
- `created_at`
- `updated_at`

## expected_rule_matches

Expected rule outcomes for a known seed.

- `seed_sha256`
- `rule_name`
- `expected_result`: `should_match` or `should_not_match`
- `expectation_type`
- `notes`

## validation_results

Observed rule outcomes compared to expectations.

- `seed_sha256`
- `rule_name`
- `observed_match`
- `expected_result`
- `validation_status`
- `matched_strings_json`
- `validated_at`

## Planned Extensions

- `clusters`
- `relationships`
- `notes`
