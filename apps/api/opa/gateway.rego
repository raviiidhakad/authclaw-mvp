package authclaw.gateway

import rego.v1

# AuthClaw Gateway OPA/Rego decision contract.
#
# Input is the sanitized opa-input/v1 document produced by OpaInputBuilder.
# Raw prompts, provider payloads, provider keys, Vault references, and
# decrypted PII must not be sent to this policy.

default allow := false
default redaction_required := false

valid_input if {
	input.sanitization_version == "opa-input/v1"
	input.tenant.id
	input.request.type == "chat.completions"
}

deny contains "malformed_or_unsupported_request" if {
	not valid_input
}

deny contains "yaml_policy_block" if {
	valid_input
	input.gateway.python_action == "block"
}

deny contains "credential_leakage" if {
	valid_input
	count(input.matches.keywords) > 0
	input.gateway.python_action == "block"
}

deny contains "disallowed_topic" if {
	valid_input
	some policy in input.policy.normalized.policies
	some rule in policy.rules
	rule.type == "content_filter"
	rule.action == "block"
	count(input.matches.keywords) > 0
}

redaction_required if {
	valid_input
	input.gateway.python_redaction_required == true
}

allow if {
	valid_input
	count(deny) == 0
}

action := "deny" if {
	count(deny) > 0
} else := "redact" if {
	count(deny) == 0
	redaction_required
} else := "allow" if {
	count(deny) == 0
	not redaction_required
}

matched_rules contains rule if {
	some reason in deny
	rule := {"id": reason, "category": reason}
}

matched_rules contains rule if {
	count(deny) == 0
	redaction_required
	rule := {"id": "pii_redaction_required", "category": "pii"}
}

decision := payload if {
	allow
	payload := {
		"allow": allow,
		"action": action,
		"reason": "OPA allowed request.",
		"matched_rules": matched_rules,
		"redaction_required": redaction_required,
		"metadata": {
			"engine": "opa",
			"schema": input.sanitization_version,
			"policy_hash": input.gateway.policy_hash,
		},
	}
}

decision := payload if {
	not allow
	reasons := [reason | some reason in deny]
	payload := {
		"allow": allow,
		"action": action,
		"reason": concat("; ", reasons),
		"matched_rules": matched_rules,
		"redaction_required": redaction_required,
		"metadata": {
			"engine": "opa",
			"schema": input.sanitization_version,
			"policy_hash": input.gateway.policy_hash,
		},
	}
}
