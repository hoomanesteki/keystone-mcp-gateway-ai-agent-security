# Results

What Keystone was measured to do, with the date and the commit of every measurement. A section is written by the tool that measured it, and a number that was not measured is not in this file.

<!-- detector:start -->
## Detector

Measured on 2026-10-23 at commit `1e796bc9ab2e`, on macOS-26.7.1-arm64-arm-64bit (10 CPUs, Python 3.12.13), by `python -m eval.detector.report`. Every number below is in `eval/results/detector-2026-10-23.json`.

The test split has 973 texts from 579 carriers, 520 of them injections. The thresholds are the configured ones: a text is flagged at 0.5 and a session is tainted at 0.85. They were checked on the dev split only (919 texts, `eval/results/tuning-2026-10-23-combined.json`): the best F0.5 of the combined score was at 0.5, and no threshold reached a precision of 0.95 for tainting, so they stayed.

The test split was scored 2 times before this report; every run is in `eval/results/test-runs.jsonl`:

- 2026-10-23, commit `755e0cd4cacf` with uncommitted changes, 200 texts, rules only: a trial of the nightly command (rules only, 200 samples) before it was moved to the dev split; no threshold was changed after it.
- 2026-10-23, commit `d5d61cde64a4`, 973 texts, all three configs.

The data (`eval/DATASETS.md` has sources and licenses). The counts are those of the whole dataset, which dev and test share between them:

- **Public prompts**: `deepset/prompt-injections`, 662 prompts of both labels, in English and German. They are direct requests to a model and not documents.
- **Documents**: emails, pages and files, harmless as they are and with one of 12 attacks from `examples/fixtures/injections/templates.yaml` put at the start, middle or end, a quarter of them hidden with invisible characters. 900 texts are generated from the fixtures of this repository, and 180 are built on articles of `Salesforce/wikitext`.
- **Hard negatives**: 150 harmless texts that sound like instructions (how-to guides, recipes, business mail, and security articles that quote attacks).

### How good the scores are

| Config | Recall at a false positive rate of 5% or less | ROC AUC | Average precision |
|---|---|---|---|
| Rules | 0.59 (95% 0.54 to 0.63) at 0.50 | 0.827 | 0.839 |
| Model | 0.32 (95% 0.28 to 0.36) at 0.96 | 0.833 | 0.819 |
| Rules and model | 0.35 (95% 0.31 to 0.39) at 0.96 | 0.884 | 0.864 |

Recall at a fixed false positive rate does not depend on the thresholds, so it is the number to compare configs by. The interval is the Wilson 95% interval of the recall.

The best ROC AUC is that of Rules and model (0.884), but at a false positive rate of 5% or less the rules alone find more attacks (0.59 against 0.35). The combined score is the higher of the two scores, so every harmless text that the model flags is flagged by it too: at 0.5 the model flags 11 of 197 harmless documents and 18 of 66 hard negatives.

### At the configured thresholds

| Config | Threshold | Precision | Recall | F1 | False positive rate |
|---|---|---|---|---|---|
| Rules | flag at 0.5 | 0.95 | 0.59 | 0.73 | 0.035 |
| Rules | taint at 0.85 | 0.99 | 0.25 | 0.40 | 0.002 |
| Model | flag at 0.5 | 0.86 | 0.38 | 0.53 | 0.068 |
| Model | taint at 0.85 | 0.87 | 0.36 | 0.51 | 0.064 |
| Rules and model | flag at 0.5 | 0.92 | 0.73 | 0.82 | 0.071 |
| Rules and model | taint at 0.85 | 0.90 | 0.53 | 0.67 | 0.064 |

### False positives on hard negatives, on their own

| Config | Hard negatives flagged (at 0.5) | Hard negatives tainting (at 0.85) | Harmless documents flagged | Harmless public prompts flagged |
|---|---|---|---|---|
| Rules | 0.24 (16 of 66, 95% 0.16 to 0.36) | 0.02 (1 of 66, 95% 0.00 to 0.08) | 0.00 (0 of 197, 95% 0.00 to 0.02) | 0.00 (0 of 190, 95% 0.00 to 0.02) |
| Model | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.06 (11 of 197, 95% 0.03 to 0.10) | 0.01 (2 of 190, 95% 0.00 to 0.04) |
| Rules and model | 0.29 (19 of 66, 95% 0.19 to 0.41) | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.06 (11 of 197, 95% 0.03 to 0.10) | 0.01 (2 of 190, 95% 0.00 to 0.04) |

The hard negatives are reported apart because a detector that flags how-to guides and business mail makes agents useless and gets switched off. By kind of text, at 0.5:

| Kind of hard negative | Rules | Model | Rules and model |
|---|---|---|---|
| business | 0.16 (3 of 19, 95% 0.06 to 0.38) | 0.21 (4 of 19, 95% 0.09 to 0.43) | 0.21 (4 of 19, 95% 0.09 to 0.43) |
| howto | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) |
| recipe | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) |
| security | 0.87 (13 of 15, 95% 0.62 to 0.96) | 0.93 (14 of 15, 95% 0.70 to 0.99) | 1.00 (15 of 15, 95% 0.80 to 1.00) |

### Public prompts and documents apart

| Config | Part | Texts | Recall at a false positive rate of 5% or less | ROC AUC |
|---|---|---|---|---|
| Rules | public | 316 (126 injections) | 0.09 (95% 0.05 to 0.15) at 0.60 | 0.544 |
| Rules | documents | 657 (394 injections) | 0.68 (95% 0.63 to 0.72) at 0.70 | 0.916 |
| Model | public | 316 (126 injections) | 0.71 (95% 0.62 to 0.78) at 0.00 | 0.877 |
| Model | documents | 657 (394 injections) | 0.12 (95% 0.09 to 0.15) at 1.00 | 0.792 |
| Rules and model | public | 316 (126 injections) | 0.73 (95% 0.65 to 0.80) at 0.00 | 0.891 |
| Rules and model | documents | 657 (394 injections) | 0.12 (95% 0.09 to 0.15) at 1.00 | 0.897 |

The attacks of the documents are the 12 templates of this repository, which were written alongside the rules, so the rules' recall on them says less than it seems to. The public prompts are the independent check. They include prompts in German, and the model's card says it is for English.

### Time of a scan

One text at a time, in milliseconds, by length (four characters make a token). The model runs on the CPU of the machine above and is given as long as it needs.

| Config | Tokens | Texts | p50 ms | p95 ms |
|---|---|---|---|---|
| Rules | under 500 | 817 | 0.1 | 0.3 |
| Rules | 500 to 2000 | 106 | 0.8 | 1.4 |
| Rules | over 2000 | 50 | 2.9 | 3.4 |
| Model | under 500 | 817 | 77.0 | 160.4 |
| Model | 500 to 2000 | 106 | 707.4 | 1115.1 |
| Model | over 2000 | 50 | 2145.3 | 4918.7 |
| Rules and model | under 500 | 817 | 77.0 | 160.4 |
| Rules and model | 500 to 2000 | 106 | 707.4 | 1115.1 |
| Rules and model | over 2000 | 50 | 2145.3 | 4918.7 |

A scan with the model runs the rules too, so the last two rows are the same scans.

### With the 300 ms wait of the gateway

The gateway waits 300 ms for the model and then goes on with the rules. This row is computed from the measured time of each scan: a text whose scan took longer is scored by its rules alone.

| Config | Recall at a false positive rate of 5% or less | Hard negatives flagged | Scans that fell back |
|---|---|---|---|
| Rules and model, 300 ms wait | 0.72 (95% 0.68 to 0.75) at 0.50 | 0.29 (19 of 66, 95% 0.19 to 0.41) | 0.16 (154 of 973, 95% 0.14 to 0.18) |

Recall at a false positive rate of 5% depends on the few harmless texts that score highest. The threshold of the rules and model row sits at 0.96, set by the harmless texts that the model gives a high score, so this row changes with which of those texts happen to be among the scans that fell back to the rules. Read it as what the wait does to this sample and not as a property of the detector.

### Recall by kind of attack (rules and model, flagged at 0.5)

| Family | Recall |
|---|---|
| evasion | 0.31 (13 of 42, 95% 0.19 to 0.46) |
| exfiltration | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| impersonation | 1.00 (62 of 62, 95% 0.94 to 1.00) |
| obfuscation | 0.89 (80 of 90, 95% 0.81 to 0.94) |
| override | 0.94 (90 of 96, 95% 0.87 to 0.97) |
| social_pressure | 1.00 (42 of 42, 95% 0.92 to 1.00) |
| tool_abuse | 0.44 (15 of 34, 95% 0.29 to 0.61) |

| Hidden with | Recall |
|---|---|
| none | 0.78 (222 of 286, 95% 0.72 to 0.82) |
| tags | 1.00 (55 of 55, 95% 0.93 to 1.00) |
| zero_width | 1.00 (53 of 53, 95% 0.93 to 1.00) |

### What is and is not in these numbers

- The model is `protectai/deberta-v3-base-prompt-injection-v2` at revision `90c9989`. Its card says it is for English and does not detect jailbreaks.
- The test split has 66 hard negatives, and each kind of them is 15 to 19 texts. A rate over so few texts is wide, and the intervals above say how wide.
- Images are not read by the scanner, so there are none in the data.
- The numbers are for one machine and one day. The times in particular move with the load of the machine (`docs/spikes/scanner.md` found five to seven times between a quiet machine and a busy one).
<!-- detector:end -->
