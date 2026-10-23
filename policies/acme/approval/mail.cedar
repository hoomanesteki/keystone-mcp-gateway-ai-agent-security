// Acme's mail rule: a message to anyone outside acme.test needs a person's approval.
//
// The recipient domain comes from the send_email extractor ($.to | domain). It is missing when
// the address is not one plain address (several recipients, a display name), and a missing domain
// is treated as external: the rule asks when it does not know.
//
// The rule is scoped to the one tool. Without the scope, `else true` would send every call of
// every tool, none of which has a recipient domain, to approval.

@id("external-email-needs-approval")
permit (principal, action == Keystone::Action::"call_tool", resource == Keystone::Tool::"mail__send_email")
when { if context.args has recipient_domain then context.args.recipient_domain != "acme.test" else true };
