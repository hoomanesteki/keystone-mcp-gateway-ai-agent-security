# Datasets of the detector evaluation

`eval/detector/datasets.py` builds the data that `eval/detector/run.py` scores (KS-707). This page
says where each part comes from, under what license, and what it can and cannot show. The numbers
are in `docs/results.md`.

## Sources

| Part | Source | License | Revision | Texts |
|---|---|---|---|---|
| Public prompts | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), train and test files | apache-2.0 (see below) | `4f61ecb038e9c3fb77e21034b22511b523772cdd` | 662: 263 labelled injection, 399 not |
| Wikipedia articles | [Salesforce/wikitext](https://huggingface.co/datasets/Salesforce/wikitext), config `wikitext-2-raw-v1`, test file | cc-by-sa-3.0 and gfdl | `b08601e04326c79dfdd32d625aee71d232d685c3` | 60 articles, each used as a harmless page |
| Fixtures | `examples/fixtures/` of this repository: 12 emails, 4 pages, 8 files | MIT, like the repository; invented text | the commit | 24 carriers |
| Generated documents | sentence banks in `eval/detector/carriers.py` | MIT; invented text | the commit | 276 carriers |
| Hard negatives | sentence banks in `eval/detector/hard.py` | MIT; invented text | the commit | 150 texts |
| Attacks | the 12 templates and 5 goals of `examples/fixtures/injections/templates.yaml` | MIT; invented text | the commit | 2 for each carrier |

I read both cards on 2026-10-23.

**deepset/prompt-injections.** The card gives `license: apache-2.0` at its top level, and a second
`license: cc-by-4.0` inside its `dataset_info` block. I take the top level as the license of the
dataset, and either one allows what is done here. The card has no description beyond its title
("deberta-v3-base-injection-dataset"), so the labels are the owner's and I did not check them. The
prompts are in English and German. The data is downloaded, not copied into the repository: the
repository holds only the sha256 of each text (`eval/detector/manifest.json`).

**WikiText-2.** The text is from Wikipedia, which is licensed cc-by-sa-3.0 and gfdl. The build
removes the tokenizing (` , `, ` @-@ `), cuts each article to one of three lengths and puts an
attack in some copies. These adapted texts exist while the evaluation runs and are not committed or
published. Credit: Merity, Xiong, Bradbury and Socher, *Pointer Sentinel Mixture Models* (2016), and
the editors of the Wikipedia articles.

## How the dataset is built

- A **carrier** is a harmless document: an email, a page or a file. There are 300 without any
  download and 60 more from WikiText-2.
- A carrier is used as a **negative** as it is, and as two **indirect positives**, each with an
  attack put at its start, middle or end. A quarter of the attacks are hidden: half with a
  zero-width space after every fourth letter of a word, half written entirely in Unicode tag
  characters. The `ks-do` marker of the naive agent is taken out of every text first.
- The **hard negatives** are harmless texts that sound like instructions: 40 how-to guides, 35
  recipes, 35 security articles that quote the attacks they warn about, and 40 mails and tickets in
  which people ask each other to do things.
- The **split** into `dev` and `test` is by carrier, from a hash of the carrier's name and a fixed
  seed, so a carrier and every attack put in it are in one split. About half of the texts are in
  each. Thresholds are tuned on `dev` (`python -m eval.detector.tune`) and the numbers that are
  published are measured on `test`.
- Every generated text is chosen by a hash of its number. `random` is not used, so a build is the
  same on every machine and every Python.

`eval/detector/manifest.json` has the sha256 of every text, with its label, kind, split and carrier.
A build is checked against it, and a text that differs stops the run with an error naming the
first five. When a part cannot be downloaded the build is without it, and the run says so on its
first lines, in the JSON and in `docs/results.md`.

```bash
uv sync --extra eval                          # pyarrow, which reads the parquet files
uv run python -m eval.detector.datasets build            # builds and checks; caches in eval/data/
uv run python -m eval.detector.datasets build --offline  # the 1,050 synthetic texts only
uv run python -m eval.detector.datasets manifest         # rewrites the manifest (a change of the data)
```

Rewriting the manifest means the data changed, and every number in `docs/results.md` is from the
data it replaced. Do it only in a branch that measures again.

## What the data can and cannot show

- The templates that make the attacks are the ones the rules were written against
  (`docs/spikes/scanner.md`). Recall on the generated documents says what the rules do with
  attacks they were built for. The public prompts are the check that does not share an author with
  the rules, and the results report the two apart.
- The public prompts are direct requests to a model. They say little about an instruction hidden in
  a long document, which is the case Keystone is built for.
- The model of the scanner is for English and its card says it does not detect jailbreaks. The
  public prompts include German and role-play requests.
- The generated documents are short and plain. Real mail has signatures, quoted threads and
  formatting that this data does not.
- 84 hard negatives in a split is not many. The results give an interval for each rate.
- Images are not read by the scanner, so none are in the data.
