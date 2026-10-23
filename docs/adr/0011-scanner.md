# ADR-0011: A scanner of rules and a classifier, and what each is for

Status: accepted
Date: 2026-10-23

## Context

A tool's output is text that someone outside the company may have written. An email, a web page or a
file can carry an instruction for the agent that reads it, and an agent that obeys it can send mail,
move money or leak a conversation. The gateway cannot tell an instruction from data by itself. It can
look for text that is made like an instruction, and it can limit what a session that read such text
may do next (the Rule of Two, KS-705).

The look has two requirements that pull apart. It runs on every output, so it has to be fast and
needs no model. And a pattern list is easy to write around, so something that learned from examples
has to stand behind it.

## Decision

**Rules first, a classifier behind them.** `defense/rules.py` is seven rules with weights, as a
reviewer can read them. `defense/classifier.py` (KS-702) is a model that scores the same text. The
final score is the larger of the two (KS-703). The demo does not depend on the model: the poisoned
email of the headline scores 0.88 from the rules alone.

**A score is the chance that at least one hit is real.** Each rule has a weight, and a text that
breaks several gets `1 - (1 - w1) * (1 - w2) * ...`. One weak rule is not enough: `tool_directive`
(0.4) and `encoded_payload` (0.2) alone stay under the 0.5 where a text becomes `suspicious`, and
two or three rules together reach 0.85 where it becomes an `injection`. The weights are the
story's starting weights. The thresholds are settings (`scanner.thresholds`) and are tuned on the
dev split of the evaluation (KS-707), never on the test split.

**What the rules read.** `hidden_unicode` reads the text as it came. The other rules read it with
the invisible characters taken out and the rest normalized (NFKC), so a zero-width space inside a
word or fullwidth letters do not hide a phrase. A zero-width character is also a hit of its own.
A tool result that is JSON is read as the strings in it: there a line break or a quote is written
with a backslash, and a phrase wrapped over two lines would otherwise be two fragments.

**Where I read the story narrowly or widely.**

- `markdown_exfil` flags an image or link whose address has a query longer than 32 characters, and
  an *image* on a host that is not allowed. The story says "image or link" for both. A link to a
  host that is not listed is ordinary text, and flagging every one would flag most pages, so a link
  needs the long query. An image is fetched without a click, so a host that is not allowed is enough.
- `hidden_unicode` uses the ranges of the description check (KS-206), with one exemption. U+200B to
  U+200F are zero-width characters and direction marks that real text uses: the joiner in an
  emoji sequence, the non-joiner in Persian, a direction mark beside Arabic, a space in Thai. One of
  those next to an emoji or a non-ASCII letter is typography and not a hit. Between two ASCII
  letters it is a hit. The tag characters, the bidirectional overrides and isolates, the word joiner
  and the invisible operators are always a hit.
- `instruction_override` has the phrase in Spanish, French, German, Portuguese and Italian as well.
  It is a phrase list and not language understanding.
- A base64 run is decoded once and the other rules read the result. If any hits, `encoded_payload_decoded`
  adds 0.5 and each rule that hit is named as `decoded:<id>` with weight 0. The decoded text is not
  decoded again.

**The marker is not a signal.** The naive agent acts on `<!--ks-do:...-->` in a result
(`examples/injections.py`, KS-708). No rule looks for it, and a test holds that. The evaluation
strips it from every text with one regex before it measures anything, because the marker carries
the attack's goal in plain text and a rule would read it there (the hidden_unicode template hides
its goal, and its marker gives it away).

**Limits.** A text is read up to `scanner.max_scan_chars` (200,000 characters); a longer one is read
at both ends, half at each, and the result says it was cut (`truncated`). Python's `re` does not let
go of the interpreter, so the limit is also the longest the gateway is busy with one scan: about
20 ms (`docs/spikes/scanner.md`). Images are not read, they are counted. A rule hit keeps up to 50
places in the text.

**The result.** `CompositeScanner.scan` returns a `ScanDetails`, which is a `ScanResult` of the
contract (section 3.6) with two more fields: `normalized` (NFKC changed the text) and `truncated`.
The contract is not changed. The rule ids that hit are in `rule_hits`.

**The classifier (KS-702).** The default is `protectai/deberta-v3-base-prompt-injection-v2`,
pinned to revision `90c9989b1a342275dd0d1a95aad283c04e075671`. I read its card, its file list and
its config on 2026-10-23.

- License: Apache-2.0, in the card and in the repository's `LICENSE` file. It is a fine-tune of
  `microsoft/deberta-v3-base`. The card lists the training sets with their licenses (Apache-2.0,
  MIT, CC-BY-3.0, CC-BY-4.0, CC0 and some with none) and gives attribution; the weights are
  published under Apache-2.0.
- Labels, from the model's `config.json`: `id2label` is `{0: "SAFE", 1: "INJECTION"}`. The score is
  the model's probability of `INJECTION`. `SPECS` in `defense/classifier.py` names every label of a
  model and what it means. A model that has a label the table does not name, or none that means
  injection, does not load, and the error lists the model's own labels, so a model retrained with
  other labels cannot be read the wrong way round. A slow test holds the table against the config.
- Limits the card states: English only (it "does not detect jailbreak attacks or handle
  non-English prompts"), and false positives on system prompts. The repository says the project is
  archived, so the model will not change, which is the other reason it is pinned.
- The optional `meta-llama/Llama-Prompt-Guard-2-86M` (revision `a8ded8e697ce7c355e395a0df51f94adb4a2fd27`)
  is gated with manual approval, under the Llama community license. Its card and config answer 401
  until the license is accepted on Hugging Face, and I did not accept it. So its label names are
  not verified: the table says `LABEL_0` is benign and `LABEL_1` is malicious, from memory, and the
  check above is what stops a wrong guess from running. That option is not tested.

*How it runs.* A text goes through the tokenizer and is cut into windows of 512 tokens (510 of the
text and the two special tokens) that overlap by 64. The score is the highest window. A window that
is 0.99 sure ends the scan, and a text of more than 32 windows is sampled across its length with the
first and the last kept. The model reads the text as the phrase rules do, invisible characters
removed and NFKC applied, with Unicode tag characters written out as the ASCII they stand for, so
that the message the `hidden_unicode` template hides is the message the model reads.

It runs in a worker thread (`anyio.to_thread`) behind a semaphore of the CPU count. The model loads
on first use, or at `warm()`, in a thread of its own, and the load goes on if the scan that asked
for it gives up. A scan that gives up (the scanner's `classifier_timeout_ms`, 300 by default)
cannot stop its thread by force. The thread looks between batches whether it was abandoned, and the
place it held in the semaphore comes back when the thread leaves and not when the caller gave up,
so abandoned scans cannot pile up when every scan times out.

*Combining.* The final score is the higher of the rules' and the model's. A model that gives no
answer in time leaves the rules' score, and `model` says `timeout`. `ScanDetails` carries both
scores, so the evaluation can read each.

*Packaging.* `keystone[scanner]` is torch and transformers. Linux gets the CPU build of torch, so
the lock holds no CUDA library. CI never installs the extra and never downloads a model, and its
image is built without the build argument. Compose builds with `WITH_SCANNER=1`, which installs the
extra and downloads the pinned model (738 MB) into the image, and the image sets
`HF_HUB_OFFLINE=1`, so the container never goes to the network for it. Started with
`docker run --network none`, the built image loaded the model from `/opt/hf-cache` and scored an
injected sentence 1.0 and a benign one 0.0. The image is 3.13 GB in `docker images` against 401 MB
without the argument: the virtualenv grows from 149 MB to 1.2 GB (torch is 652 MB of it) and the
model cache is 715 MB (`du -sh`). The first build took 20 minutes on a laptop. `make gate`
installs the extra from Phase 7, because the gate runs the one test that loads the real model.
Without the extra, `load_classifier` logs `scanner_classifier_unavailable` once and the scanner
runs on its rules. `KEYSTONE_SCANNER_CLASSIFIER=none` (or `scanner.classifier: none`) turns the
model off.

## Consequences

- The rules miss what no pattern names: a goal in other words, a language that is not listed, a
  payload under 200 characters of base64, a request to open a web address. Three of the twelve
  planted templates score 0.4 and one scores 0 (`docs/spikes/scanner.md`). The evaluation (KS-707)
  is where recall is measured, and the Rule of Two is what holds when the scanner misses.
- The rules flag text that explains an attack as readily as text that makes one. A security
  article that quotes "ignore all previous instructions" scores like an attack. That is a hard
  negative the evaluation reports on its own.
- A business email that says "please send the invoice to bob@example.com" scores 0.4 on
  `tool_directive` alone, and stays benign. With "do not tell the user" in the same text it is
  suspicious. That is the weighting working as intended and also its cost.
- At the default timeout the model reads about 3,500 characters on this machine, and anything
  longer is scored by the rules alone. Latency is close to linear in length (about 0.08 ms of wall
  time and 0.14 to 0.2 ms of CPU for each character) and five to seven times worse on a busy
  machine (`docs/spikes/scanner.md`). `scanner.classifier_timeout_ms` is the lever, and each
  millisecond of it can be added to a call.
- The model is sure of a short text that is only an attack, and often loses the same instruction
  inside a longer ordinary email or page (0.00 to 0.004 on four of the six planted pieces). The
  rules caught three of those four. One planted email, m15, is missed by both. The final score is a
  maximum because the two miss different things.
- The model is English only and can be wrong about imperative text: one how-to sentence scored
  0.9996. A false positive costs a warning wrapped round the output for a low-risk tool, and the
  redaction or the withholding of a high-risk or critical one (KS-703), so the evaluation reports
  the false-positive rate on hard negatives apart from the overall rate.
- The first scans after a start find the model still loading (3.4 s from the cache, 10 to 13 s on a
  busy machine) and fall back to the rules. `warm()` is for the start-up code to call.
- The lower-case views make the rules about twice as fast and make their places in the text
  unreliable for cutting. `hidden_unicode` and `markdown_exfil` are the rules whose places are
  used to cut a text (KS-703), and they are run again on the text as it came.

## Revisit when

The evaluation shows a rule that is wrong more often than right at its weight, the gateway needs
to scan outputs of several megabytes (then the rules move out of the process, or the scan is split
and yields between pieces), or the model is too slow for the outputs a deployment has (a quantized
or ONNX copy, or a smaller model, would be measured against the same dev split first).
