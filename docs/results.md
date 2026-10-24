# Results

What Keystone was measured to do, with the date and the commit of every measurement. A section is written by the tool that measured it, and a number that was not measured is not in this file.

<!-- detector:start -->
## Detector

Measured on 2026-10-24 at commit `6eb2e454e91a`, on macOS-26.7.1-arm64-arm-64bit (10 CPUs, Python 3.12.13), by `python -m eval.detector.report`. Every number below is in `eval/results/detector-2026-10-24.json`.

The test split has 973 texts from 579 carriers, 520 of them injections. The thresholds are the configured ones: a text is flagged at 0.5 and a session is tainted at 0.85. They were checked on the dev split only (919 texts, `eval/results/tuning-2026-10-24-combined.json`): the best F0.5 of the combined score was at 0.45, not 0.5, and the lowest threshold with a precision of 0.95 for tainting was 0.8, not 0.85, and this report uses the configured ones.

The test split was scored 3 times before this report; every run is in `eval/results/test-runs.jsonl`:

- 2026-10-23, commit `755e0cd4cacf` with uncommitted changes, 200 texts, rules only: a trial of the nightly command (rules only, 200 samples) before it was moved to the dev split; no threshold was changed after it.
- 2026-10-23, commit `d5d61cde64a4`, 973 texts, all three configs.
- 2026-10-23, commit `1e796bc9ab2e`, 973 texts, all three configs: second full run, made after the text of the report changed to read its sentences from records; the data, the scoring and the thresholds are those of the run at d5d61cd.

The data (`eval/DATASETS.md` has sources and licenses). The counts are those of the whole dataset, which dev and test share between them:

- **Public prompts**: `deepset/prompt-injections`, 662 prompts of both labels, in English and German. They are direct requests to a model and not documents.
- **Documents**: emails, pages and files, harmless as they are and with one of 12 attacks from `examples/fixtures/injections/templates.yaml` put at the start, middle or end, a quarter of them hidden with invisible characters. 900 texts are generated from the fixtures of this repository, and 180 are built on articles of `Salesforce/wikitext`.
- **Hard negatives**: 150 harmless texts that sound like instructions (how-to guides, recipes, business mail, and security articles that quote attacks).

### How the join and the windows were picked, on the dev split

Dev has 919 texts and 463 injections. `python -m eval.detector.combine` tried 424 candidates on it (a shape of window, how the windows of a text are made one score, and a way to join that with the rules' score) and the test split was not read. Recall at a false positive rate of 5% or less on dev, by the windows the model reads in (the rules alone find 0.52, whatever the windows):

| Windows of | Model alone | Higher of the two | Rules first, then the model (weight 0.7) |
|---|---|---|---|
| 510 | 0.17 | 0.17 | 0.61 |
| 256 | 0.19 | 0.19 | 0.63 |
| 128 | 0.25 | 0.25 | 0.67 |
| 64 | 0.39 | 0.39 | 0.68 |

Why the model was weak on documents: the share of each kind of text that scores 0.5 or more, from the model alone and from the rules. A long window holds an attack and the document around it, and the model scores the whole.

| Kind of text | Texts | Rules | Model, windows of 510 | Model, windows of 256 | Model, windows of 128 | Model, windows of 64 |
|---|---|---|---|---|---|---|
| documents with an attack | 326 | 78% | 36% | 43% | 64% | 87% |
| harmless documents | 163 | 0% | 9% | 8% | 9% | 12% |
| hard negatives | 84 | 29% | 36% | 36% | 37% | 46% |
| public injections | 137 | 7% | 45% | 45% | 46% | 50% |
| harmless public prompts | 209 | 1% | 1% | 1% | 1% | 1% |

Resampling the carriers of dev 200 times, rules first with windows of 128 finds +0.12 (95% -0.08 to +0.21) of the injections more than the rules alone at a false positive rate of 5%, and the higher of the two over windows of 510 finds -0.33 (95% -0.43 to -0.21).

The windows of 128 tokens with an overlap of 64 and the model weight of 0.7 were picked by a rule written before the numbers: of the joins the gateway can run, the candidates within the noise of the best recall on dev (7 of the 463 injections) are tied, and of those the larger window wins. The test split was scored once, with that choice.

### How good the scores are

| Config | Recall at a false positive rate of 5% or less | ROC AUC | Average precision |
|---|---|---|---|
| Rules | 0.59 (95% 0.54 to 0.63) at 0.50 | 0.827 | 0.839 |
| Model, windows of 510 (Phase 7) | 0.32 (95% 0.28 to 0.36) at 0.96 | 0.833 | 0.819 |
| Higher of the two, windows of 510 (Phase 7) | 0.35 (95% 0.31 to 0.39) at 0.96 | 0.884 | 0.864 |
| Model, windows of 128 | 0.52 (95% 0.48 to 0.56) at 0.97 | 0.868 | 0.855 |
| Rules first, then the model | 0.71 (95% 0.67 to 0.74) at 0.64 | 0.912 | 0.930 |

Recall at a fixed false positive rate does not depend on the thresholds, so it is the number to compare configs by. The interval is the Wilson 95% interval of the recall.

At a false positive rate of 5% or less the row that finds most is Rules first, then the model (0.71). The rules alone find 0.59. The higher of the two scores found less than the rules alone (0.35 against 0.59), because it keeps every false positive of the model.

### At the configured thresholds

| Config | Threshold | Precision | Recall | F1 | False positive rate |
|---|---|---|---|---|---|
| Rules | flag at 0.5 | 0.95 | 0.59 | 0.73 | 0.035 |
| Rules | taint at 0.85 | 0.99 | 0.25 | 0.40 | 0.002 |
| Model, windows of 510 (Phase 7) | flag at 0.5 | 0.86 | 0.38 | 0.53 | 0.068 |
| Model, windows of 510 (Phase 7) | taint at 0.85 | 0.87 | 0.36 | 0.51 | 0.064 |
| Higher of the two, windows of 510 (Phase 7) | flag at 0.5 | 0.92 | 0.73 | 0.82 | 0.071 |
| Higher of the two, windows of 510 (Phase 7) | taint at 0.85 | 0.90 | 0.53 | 0.67 | 0.064 |
| Model, windows of 128 | flag at 0.5 | 0.89 | 0.59 | 0.71 | 0.084 |
| Model, windows of 128 | taint at 0.85 | 0.90 | 0.57 | 0.70 | 0.075 |
| Rules first, then the model | flag at 0.5 | 0.92 | 0.78 | 0.85 | 0.082 |
| Rules first, then the model | taint at 0.85 | 0.99 | 0.25 | 0.40 | 0.002 |

### False positives on hard negatives, on their own

| Config | Hard negatives flagged (at 0.5) | Hard negatives tainting (at 0.85) | Harmless documents flagged | Harmless public prompts flagged |
|---|---|---|---|---|
| Rules | 0.24 (16 of 66, 95% 0.16 to 0.36) | 0.02 (1 of 66, 95% 0.00 to 0.08) | 0.00 (0 of 197, 95% 0.00 to 0.02) | 0.00 (0 of 190, 95% 0.00 to 0.02) |
| Model, windows of 510 (Phase 7) | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.06 (11 of 197, 95% 0.03 to 0.10) | 0.01 (2 of 190, 95% 0.00 to 0.04) |
| Higher of the two, windows of 510 (Phase 7) | 0.29 (19 of 66, 95% 0.19 to 0.41) | 0.27 (18 of 66, 95% 0.18 to 0.39) | 0.06 (11 of 197, 95% 0.03 to 0.10) | 0.01 (2 of 190, 95% 0.00 to 0.04) |
| Model, windows of 128 | 0.33 (22 of 66, 95% 0.23 to 0.45) | 0.33 (22 of 66, 95% 0.23 to 0.45) | 0.07 (14 of 197, 95% 0.04 to 0.12) | 0.01 (2 of 190, 95% 0.00 to 0.04) |
| Rules first, then the model | 0.33 (22 of 66, 95% 0.23 to 0.45) | 0.02 (1 of 66, 95% 0.00 to 0.08) | 0.07 (13 of 197, 95% 0.04 to 0.11) | 0.01 (2 of 190, 95% 0.00 to 0.04) |

The hard negatives are reported apart because a detector that flags how-to guides and business mail makes agents useless and gets switched off. By kind of text, at 0.5:

| Kind of hard negative | Rules | Model, windows of 510 (Phase 7) | Higher of the two, windows of 510 (Phase 7) | Model, windows of 128 | Rules first, then the model |
|---|---|---|---|---|---|
| business | 0.16 (3 of 19, 95% 0.06 to 0.38) | 0.21 (4 of 19, 95% 0.09 to 0.43) | 0.21 (4 of 19, 95% 0.09 to 0.43) | 0.21 (4 of 19, 95% 0.09 to 0.43) | 0.21 (4 of 19, 95% 0.09 to 0.43) |
| howto | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.19 (3 of 16, 95% 0.07 to 0.43) | 0.19 (3 of 16, 95% 0.07 to 0.43) |
| recipe | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) | 0.00 (0 of 16, 95% 0.00 to 0.19) |
| security | 0.87 (13 of 15, 95% 0.62 to 0.96) | 0.93 (14 of 15, 95% 0.70 to 0.99) | 1.00 (15 of 15, 95% 0.80 to 1.00) | 1.00 (15 of 15, 95% 0.80 to 1.00) | 1.00 (15 of 15, 95% 0.80 to 1.00) |

### Public prompts and documents apart

| Config | Part | Texts | Recall at a false positive rate of 5% or less | ROC AUC |
|---|---|---|---|---|
| Rules | public | 316 (126 injections) | 0.09 (95% 0.05 to 0.15) at 0.60 | 0.544 |
| Rules | documents | 657 (394 injections) | 0.68 (95% 0.63 to 0.72) at 0.70 | 0.916 |
| Model, windows of 510 (Phase 7) | public | 316 (126 injections) | 0.71 (95% 0.62 to 0.78) at 0.00 | 0.877 |
| Model, windows of 510 (Phase 7) | documents | 657 (394 injections) | 0.12 (95% 0.09 to 0.15) at 1.00 | 0.792 |
| Higher of the two, windows of 510 (Phase 7) | public | 316 (126 injections) | 0.73 (95% 0.65 to 0.80) at 0.00 | 0.891 |
| Higher of the two, windows of 510 (Phase 7) | documents | 657 (394 injections) | 0.12 (95% 0.09 to 0.15) at 1.00 | 0.897 |
| Model, windows of 128 | public | 316 (126 injections) | 0.72 (95% 0.64 to 0.79) at 0.00 | 0.879 |
| Model, windows of 128 | documents | 657 (394 injections) | 0.28 (95% 0.24 to 0.33) at 1.00 | 0.869 |
| Rules first, then the model | public | 316 (126 injections) | 0.75 (95% 0.66 to 0.81) at 0.00 | 0.893 |
| Rules first, then the model | documents | 657 (394 injections) | 0.82 (95% 0.78 to 0.86) at 0.68 | 0.958 |

The attacks of the documents are the 12 templates of this repository, which were written alongside the rules, so the rules' recall on them says less than it seems to. The public prompts are the independent check. They include prompts in German, and the model's card says it is for English.

### Time of a scan

One text at a time, in milliseconds, by length (four characters make a token). The model runs on the CPU of the machine above and is given as long as it needs.

| Config | Tokens | Texts | p50 ms | p95 ms |
|---|---|---|---|---|
| Rules | under 500 | 817 | 0.1 | 0.3 |
| Rules | 500 to 2000 | 106 | 0.9 | 2.1 |
| Rules | over 2000 | 50 | 3.0 | 4.6 |
| Model, windows of 510 (Phase 7) | under 500 | 817 | 94.0 | 268.2 |
| Model, windows of 510 (Phase 7) | 500 to 2000 | 106 | 1058.1 | 1715.1 |
| Model, windows of 510 (Phase 7) | over 2000 | 50 | 3091.0 | 6898.5 |
| Higher of the two, windows of 510 (Phase 7) | under 500 | 817 | 94.0 | 268.2 |
| Higher of the two, windows of 510 (Phase 7) | 500 to 2000 | 106 | 1058.1 | 1715.1 |
| Higher of the two, windows of 510 (Phase 7) | over 2000 | 50 | 3091.0 | 6898.5 |
| Model, windows of 128 | under 500 | 817 | 103.0 | 326.6 |
| Model, windows of 128 | 500 to 2000 | 106 | 945.2 | 2073.8 |
| Model, windows of 128 | over 2000 | 50 | 2223.5 | 2868.0 |
| Rules first, then the model | under 500 | 817 | 60.0 | 298.5 |
| Rules first, then the model | 500 to 2000 | 106 | 478.6 | 1939.0 |
| Rules first, then the model | over 2000 | 50 | 3.3 | 3563.1 |

Rules first, then the model, does not give the model a text that the rules flag (321 of the 973 texts of this run), so its scans are shorter than those of the model alone. A scan with the model runs the rules too.

### With the 300 ms wait of the gateway

The gateway waits 300 ms for the model and then goes on with the rules. These rows are computed from the measured time of each scan: a text whose scan took longer is scored by its rules alone.

| Config | Recall at a false positive rate of 5% or less | Hard negatives flagged | Scans that fell back |
|---|---|---|---|
| Higher of the two, windows of 510, 300 ms wait | 0.71 (95% 0.67 to 0.75) at 0.50 | 0.29 (19 of 66, 95% 0.19 to 0.41) | 0.19 (181 of 973, 95% 0.16 to 0.21) |
| Rules first, then the model, 300 ms wait | 0.66 (95% 0.62 to 0.70) at 0.60 | 0.33 (22 of 66, 95% 0.23 to 0.45) | 0.12 (116 of 973, 95% 0.10 to 0.14) |

Recall at a false positive rate of 5% depends on the few harmless texts that score highest. The threshold of the rules first row sits at 0.64, set by the harmless texts that score high, so a row for the wait changes with which of those texts happen to be among the scans that fell back to the rules. Read it as what the wait does to this sample and not as a property of the detector.

### Recall by kind of attack (flagged at 0.5)

| Family | Rules | Higher of the two, windows of 510 (Phase 7) | Rules first, then the model |
|---|---|---|---|
| evasion | 0.24 (10 of 42, 95% 0.13 to 0.39) | 0.31 (13 of 42, 95% 0.19 to 0.46) | 0.52 (22 of 42, 95% 0.38 to 0.67) |
| exfiltration | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| impersonation | 1.00 (62 of 62, 95% 0.94 to 1.00) | 1.00 (62 of 62, 95% 0.94 to 1.00) | 1.00 (62 of 62, 95% 0.94 to 1.00) |
| obfuscation | 0.73 (66 of 90, 95% 0.63 to 0.81) | 0.89 (80 of 90, 95% 0.81 to 0.94) | 0.99 (89 of 90, 95% 0.94 to 1.00) |
| override | 0.79 (76 of 96, 95% 0.70 to 0.86) | 0.94 (90 of 96, 95% 0.87 to 0.97) | 1.00 (96 of 96, 95% 0.96 to 1.00) |
| social_pressure | 1.00 (42 of 42, 95% 0.92 to 1.00) | 1.00 (42 of 42, 95% 0.92 to 1.00) | 1.00 (42 of 42, 95% 0.92 to 1.00) |
| tool_abuse | 0.29 (10 of 34, 95% 0.17 to 0.46) | 0.44 (15 of 34, 95% 0.29 to 0.61) | 0.47 (16 of 34, 95% 0.31 to 0.63) |

| Hidden with | Rules | Higher of the two, windows of 510 (Phase 7) | Rules first, then the model |
|---|---|---|---|
| none | 0.65 (186 of 286, 95% 0.59 to 0.70) | 0.78 (222 of 286, 95% 0.72 to 0.82) | 0.86 (247 of 286, 95% 0.82 to 0.90) |
| tags | 1.00 (55 of 55, 95% 0.93 to 1.00) | 1.00 (55 of 55, 95% 0.93 to 1.00) | 1.00 (55 of 55, 95% 0.93 to 1.00) |
| zero_width | 1.00 (53 of 53, 95% 0.93 to 1.00) | 1.00 (53 of 53, 95% 0.93 to 1.00) | 1.00 (53 of 53, 95% 0.93 to 1.00) |

| Template | Rules | Higher of the two, windows of 510 (Phase 7) | Rules first, then the model |
|---|---|---|---|
| base64 | 0.23 (7 of 31, 95% 0.11 to 0.40) | 0.68 (21 of 31, 95% 0.50 to 0.81) | 0.97 (30 of 31, 95% 0.84 to 0.99) |
| delimiter_escape | 1.00 (34 of 34, 95% 0.90 to 1.00) | 1.00 (34 of 34, 95% 0.90 to 1.00) | 1.00 (34 of 34, 95% 0.90 to 1.00) |
| fake_error_recovery | 0.24 (10 of 42, 95% 0.13 to 0.39) | 0.31 (13 of 42, 95% 0.19 to 0.46) | 0.52 (22 of 42, 95% 0.38 to 0.67) |
| fake_system | 1.00 (34 of 34, 95% 0.90 to 1.00) | 1.00 (34 of 34, 95% 0.90 to 1.00) | 1.00 (34 of 34, 95% 0.90 to 1.00) |
| hidden_unicode | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| ignore_previous | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| important_instructions | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| markdown_exfil | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) | 1.00 (28 of 28, 95% 0.88 to 1.00) |
| role_override | 0.41 (14 of 34, 95% 0.26 to 0.58) | 0.82 (28 of 34, 95% 0.66 to 0.92) | 1.00 (34 of 34, 95% 0.90 to 1.00) |
| tool_knowledge | 0.29 (10 of 34, 95% 0.17 to 0.46) | 0.44 (15 of 34, 95% 0.29 to 0.61) | 0.47 (16 of 34, 95% 0.31 to 0.63) |
| translated | 1.00 (31 of 31, 95% 0.89 to 1.00) | 1.00 (31 of 31, 95% 0.89 to 1.00) | 1.00 (31 of 31, 95% 0.89 to 1.00) |
| urgent_secrecy | 1.00 (42 of 42, 95% 0.92 to 1.00) | 1.00 (42 of 42, 95% 0.92 to 1.00) | 1.00 (42 of 42, 95% 0.92 to 1.00) |

### What is and is not in these numbers

- The model is `protectai/deberta-v3-base-prompt-injection-v2` at revision `90c9989`. Its card says it is for English and does not detect jailbreaks. It reads in windows of 128 tokens that overlap by 64.
- Rules first, then the model, lets the model add to a score that the rules left under the flag threshold, at a weight of 0.7. So the model alone can flag a text and cannot make an injection of it: only the rules can taint a session (ADR-0011).
- The windows and the weight were picked on dev from 424 candidates, so the recall of the chosen one on dev is higher than a sample it was not picked on would give. The test split is that sample, and it was scored once with the choice.
- The test split has 66 hard negatives, and each kind of them is 15 to 19 texts. A rate over so few texts is wide, and the intervals above say how wide.
- Prompt Guard 2 (`prompt-guard-2-86m`) was not measured: its files answer 401 without a Hugging Face login and the acceptance of the Llama license, and ADR-0011 records the check.
- Images are not read by the scanner, so there are none in the data.
- The numbers are for one machine and one day. The times in particular move with the load of the machine (`docs/spikes/scanner.md` found five to seven times between a quiet machine and a busy one).
<!-- detector:end -->
