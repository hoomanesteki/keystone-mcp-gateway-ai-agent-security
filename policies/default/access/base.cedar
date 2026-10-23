// The access rules every tenant starts with (plan section 3.8). Cedar denies a call unless one
// permit matches and no forbid does, so a tool that none of these reaches is out of bounds.
//
// Risk levels: 1 low, 2 medium, 3 high, 4 critical. A tool's risk comes from the upstream config.
// Both actions are covered: `list_tool` decides what a caller sees, `call_tool` what it may run.

@id("same-tenant-low-medium")
permit (principal, action in [Keystone::Action::"list_tool", Keystone::Action::"call_tool"], resource)
when { resource.tenant == principal.tenant && resource.risk_level <= 2 };

@id("operators-high")
permit (principal in Keystone::Group::"operators", action, resource)
when { resource.tenant == principal.tenant && resource.risk_level == 3 };

@id("admins-critical")
permit (principal in Keystone::Group::"admins", action, resource)
when { resource.tenant == principal.tenant && resource.risk_level == 4 };

@id("deny-cross-tenant")
forbid (principal, action, resource) unless { resource.tenant == principal.tenant };
