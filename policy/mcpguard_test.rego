package mcpguard_test

import data.mcpguard

long_body := concat("", ["x" | some _ in numbers.range(1, 2001)])

read(path) := {"server": "demo", "tool": "read_file", "arguments": {"path": path}, "requires_approval": false, "approved": null}

email(body, approved) := {
	"server": "demo",
	"tool": "send_email",
	"arguments": {"to": "alice@example.com", "subject": "s", "body": body},
	"requires_approval": true,
	"approved": approved,
}

test_read_in_workspace_allowed if {
	d := mcpguard.decision with input as read("/workspace/README.md")
	d.allow == true
	d.reasons == []
}

test_read_secrets_denied if {
	d := mcpguard.decision with input as read("/workspace/secrets/prod.env")
	d.allow == false
	d.reasons == ["reading files under /workspace/secrets/ is not allowed"]
}

test_email_with_approval_allowed if {
	d := mcpguard.decision with input as email("hello", true)
	d.allow == true
}

test_email_without_approval_denied if {
	d := mcpguard.decision with input as email("hello", null)
	d.allow == false
	"send_email requires a recorded human approval" in d.reasons
}

test_long_email_denied if {
	d := mcpguard.decision with input as email(long_body, true)
	d.allow == false
	d.reasons == ["email body is longer than 2000 characters"]
}

test_fetch_from_other_server_denied if {
	d := mcpguard.decision with input as {"server": "crm", "tool": "fetch_url", "arguments": {"url": "https://docs.python.org/"}, "approved": null}
	d.allow == false
	d.reasons == ["server \"crm\" may not fetch URLs"]
}

test_unknown_tool_denied_by_default if {
	d := mcpguard.decision with input as {"server": "demo", "tool": "delete_repository", "arguments": {}}
	d.allow == false
	d.reasons == ["no organisation rule covers this tool"]
}

test_several_reasons_reported_together if {
	d := mcpguard.decision with input as email(long_body, false)
	count(d.reasons) == 2
}
