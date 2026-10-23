// The Rule of Two, the part that forbids (plan sections 3.5 and 3.8, KS-705).
//
// A session that read an injection is tainted (KS-704). A tainted session never runs a critical
// tool. A forbid beats every permit, so this holds for the tools that admins-critical lets through
// and for any rule a tenant adds on top.

@id("deny-critical-when-tainted")
forbid (principal, action == Keystone::Action::"call_tool", resource)
when { context.session_tainted && resource.risk_level == 4 };
