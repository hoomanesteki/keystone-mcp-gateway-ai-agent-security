// Rules that go with the demo bank upstream. They are read when policy.include_demo is on.
//
// A transfer over 500 needs a person's approval. The transfer tool's extractor reads the amount
// in cents ($.amount | cents, in the upstream config), so the limit is 50000: written in whole
// units, a transfer of 500.99 would be cut down to 500 and slip under it.
//
// An amount that could not be read is not treated as small. A rule that stays silent when it does
// not know lets the unusual call through; this one asks.

@id("approve-transfer-over-500")
permit (principal, action == Keystone::Action::"call_tool", resource == Keystone::Tool::"bank__transfer")
when { if context.args has amount then context.args.amount > 50000 else true };
