// The Rule of Two, the part that asks (plan sections 3.5 and 3.8, KS-705).
//
// An agent session should not combine all three of these without a person in the loop:
//   A  it processes untrusted input     (session flag reads_untrusted)
//   B  it has access to sensitive data  (session flag reads_sensitive)
//   C  it changes state or sends data out (tool tag external_effect)
// The flags come from the tags of the tools the session has called (KS-704). C is the tool being
// called. Both rules below ask a person: they never block, and they never look at the arguments.

@id("rule-of-two")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { resource.tags.contains("external_effect")
       && context.session_flags.contains("reads_untrusted")
       && context.session_flags.contains("reads_sensitive") };

// A session that read an injection has already been steered once, so even a session that never
// touched sensitive data asks before it does anything outside.
@id("tainted-external-effect")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { context.session_tainted && resource.tags.contains("external_effect") };

// A session that has read untrusted text asks before any external effect, whatever else it read
// (ADR-0018). The red team found that phishing a colleague or overwriting a file needs no
// sensitive data, so the rule above never asked about the attacks that landed. A tenant that
// accepts the cost lists this id under `exclude_default_policies` in its config.
@id("untrusted-then-external-effect")
permit (principal, action == Keystone::Action::"call_tool", resource)
when { resource.tags.contains("external_effect")
       && context.session_flags.contains("reads_untrusted") };
