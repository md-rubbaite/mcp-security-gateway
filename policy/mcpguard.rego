# Organisation rules for mcpguard, evaluated by Open Policy Agent (OPA 1.x, Rego v1).
#
# mcpguard asks OPA only after its own TOML policy has allowed a call, and forwards the call only if
# this decision also allows it. OPA can therefore add restrictions but never loosen the local policy.
#
# Input (sent by mcpguard for every tools/call):
#   {"server": "demo", "tool": "read_file", "arguments": {...},
#    "requires_approval": false, "approved": null | true | false}
# Output at data.mcpguard.decision:
#   {"allow": bool, "reasons": [string]}
package mcpguard

default decision := {"allow": false, "reasons": ["no organisation rule covers this tool"]}

decision := {"allow": count(deny) == 0, "reasons": sort(deny)} if {
	input.tool in known_tools
}

known_tools := {"read_file", "fetch_url", "send_email"}

# Servers allowed to reach the internet through fetch_url.
fetch_servers := {"demo", "docs"}

# Files under a secrets folder stay off limits even if a local policy is edited to allow them.
deny contains "reading files under /workspace/secrets/ is not allowed" if {
	input.tool == "read_file"
	startswith(input.arguments.path, "/workspace/secrets/")
}

# Every email needs a recorded human approval (defence in depth against a mis-edited TOML policy).
deny contains "send_email requires a recorded human approval" if {
	input.tool == "send_email"
	not input.approved == true
}

# Very long outbound emails are treated as a data-loss signal.
deny contains "email body is longer than 2000 characters" if {
	input.tool == "send_email"
	count(input.arguments.body) > 2000
}

deny contains msg if {
	input.tool == "fetch_url"
	not input.server in fetch_servers
	msg := sprintf("server %q may not fetch URLs", [input.server])
}
