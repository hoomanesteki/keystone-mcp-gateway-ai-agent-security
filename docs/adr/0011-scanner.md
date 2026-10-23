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
- The lower-case views make the rules about twice as fast and make their places in the text
  unreliable for cutting. `hidden_unicode` and `markdown_exfil` are the rules whose places are
  used to cut a text (KS-703), and they are run again on the text as it came.

## Revisit when

The evaluation shows a rule that is wrong more often than right at its weight, or the gateway needs
to scan outputs of several megabytes (then the rules move out of the process, or the scan is
split and yields between pieces).
