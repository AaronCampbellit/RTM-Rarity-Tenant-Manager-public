package securityops

import (
	"strings"

	"github.com/rarity/rtm/internal/model"
)

// remediationPlan turns normalized evidence into conservative response
// guidance. The classifier deliberately uses both stable RTM rule IDs and
// provider-controlled titles/alerts so Defender and native incidents receive
// the same experience. Guidance is conditional where the evidence does not
// prove compromise.
func remediationPlan(incident model.SecurityIncidentDetail) model.SecurityRemediationPlan {
	text := remediationText(incident)
	switch {
	case containsAny(text, "phish", "malicious message", "malicious url", "credential harvesting"):
		return phishingPlan()
	case containsAny(text, "forward", "inbox rule", "transport rule", "connector", "mailbox delegation", "mailbox permission", "send as", "send on behalf"):
		return mailboxPlan()
	case containsAny(text, "app consent", "oauth", "app role assignment", "service principal", "service-principal owner", "application permission", "application credential", "application secret", "application owner", "application_owner_change", "high-risk application", "high privileges"):
		return applicationPlan()
	case containsAny(text, "sharepoint", "onedrive", "external sharing", "anonymous link", "bulk file", "file deletion", "file download"):
		return dataAccessPlan()
	case containsAny(text, "conditional access", "named location", "security defaults", "authorization policy", "cross-tenant access", "domain federation", "federation settings", "hybrid authentication", "dirsync", "desktop sso", "passthrough authentication", "mail protection", "anti-phish", "anti-spam", "anti-malware", "safe links", "safe attachments", "quarantine policy", "audit configuration", "audit disabled", "audit bypass", "unified audit", "adminauditlog"):
		return controlChangePlan()
	case containsAny(text, "audit log search", "auditlogsearch", "search-unifiedauditlog", "compliance search", "compliancesearch"):
		return auditEvidencePlan()
	case containsAny(text, "privileged role", "role membership", "guest privilege", "group owner", "large group membership", "group membership"):
		return privilegePlan()
	case containsAny(text, "sign-in", "signin", "password spray", "impossible travel", "session", "token reuse", "legacy authentication", "mfa change", "authentication method", "suspicious authentication", "fraud reported", "unusual administrator", "administrator activity burst", "administrative failure", "changed many objects", "cross-tenant administrator"):
		return identityPlan()
	case containsAny(text, "user account", "account lifecycle", "password reset", "guest user", "guest invitation"):
		return accountChangePlan()
	default:
		return genericPlan()
	}
}

func remediationText(incident model.SecurityIncidentDetail) string {
	parts := []string{incident.RuleID, incident.Title, incident.Description, incident.Source}
	if incident.Evidence != nil {
		parts = append(parts, incident.Evidence.Operation, incident.Evidence.Workload, incident.Evidence.RelatedResource)
	}
	for _, alert := range incident.Alerts {
		parts = append(parts, alert.Title, alert.DetectionSource, alert.ServiceSource)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func containsAny(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func step(phase, urgency, title, description, action string) model.SecurityRemediationStep {
	return model.SecurityRemediationStep{Phase: phase, Urgency: urgency, Title: title, Description: description, RTMAction: action}
}

func identityPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Identity compromise",
		Summary:  "Treat the identity as potentially compromised until the user and sign-in evidence establish otherwise.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Stop active access", "If the activity is not immediately verified, block sign-in, revoke sessions, reset the password, and remove unrecognized authentication methods. Keep the account blocked while investigating.", "Users → Revoke user access (What-If)"),
			step("Investigate", "High", "Validate the sign-in sequence", "Review successful and failed sign-ins around the incident for IP, country, device, client app, protocol, session, and Conditional Access differences. Confirm the activity directly with the user through a trusted channel.", "Raw Event Explorer → search the user and client IP"),
			step("Investigate", "High", "Look for post-compromise activity", "Search for new MFA methods, password resets, mailbox rules, forwarding, app consents, role or group changes, and unusual file access performed after the first suspicious sign-in.", "Security Operations → related incidents"),
			step("Recover", "Standard", "Restore trusted access", "Require fresh credentials and trusted MFA registration. Re-enable sign-in only after the user's devices and authentication methods are verified and any malicious persistence is removed.", "Users → review account and MFA state"),
			step("Validate", "Standard", "Monitor for recurrence", "Confirm there are no new suspicious sign-ins or changes from the same identity, IP, session, or device during the monitoring window before resolving the incident.", "Raw Event Explorer → repeat the evidence search"),
		},
		CompletionCriteria: []string{"The user has confirmed which activity was legitimate.", "Active sessions and unknown authentication methods have been addressed.", "No unauthorized mailbox, application, role, group, or file changes remain.", "Follow-up monitoring shows no recurrence."},
	}
}

func mailboxPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Mailbox persistence or mail-flow change",
		Summary:  "Contain unauthorized mail access or routing without destroying the audit evidence needed to scope the incident.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Disable the unapproved change", "Confirm the business owner and destination. If unapproved, remove or disable the forwarding address, inbox rule, transport rule, connector, or delegate permission while preserving its values in the incident record.", "Exchange → run the matching What-If action"),
			step("Contain", "Immediate", "Secure the actor and mailbox", "If the actor or mailbox owner did not authorize the change, block the affected identity, revoke sessions, reset the password, and review registered MFA methods.", "Users → Revoke user access (What-If)"),
			step("Investigate", "High", "Determine exposure", "Review mailbox audit activity from the first suspicious access through containment. Check related rule changes, delegate grants, sent items, message access, and whether externally forwarded messages contained sensitive data.", "Raw Event Explorer → search mailbox, actor, and destination"),
			step("Eradicate", "High", "Remove alternate persistence", "Inspect all inbox rules, forwarding settings, delegates, transport rules, connectors, and application consents associated with the mailbox or actor; remove only unauthorized entries.", "Exchange → Mail Flow and Access"),
			step("Validate", "Standard", "Verify normal mail flow", "Send controlled test messages, confirm approved delivery and forwarding behavior, and monitor for the rule or destination being recreated before resolving.", "Exchange → refresh mailbox details"),
		},
		CompletionCriteria: []string{"The mail-flow or permission change has an approved owner or has been removed.", "The initiating identity has been verified or contained.", "The exposure window and affected messages are documented.", "No unauthorized rule, delegate, connector, consent, or forwarding setting remains."},
	}
}

func applicationPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Application or consent risk",
		Summary:  "Treat unexpected application permissions or credentials as durable tenant access until their owner and use are verified.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Stop unauthorized application access", "If the application, consent, permission, or credential is unapproved, disable the service principal or revoke the specific grant and credential. Do not delete the object until identifiers and permissions are preserved as evidence.", "Entra admin center → Enterprise applications"),
			step("Investigate", "High", "Establish owner, permissions, and use", "Identify the publisher, owners, consent actor, credential creator, delegated and application permissions, affected users, and sign-in activity. Determine what data the granted scopes allowed the app to access.", "Raw Event Explorer → search application and actor"),
			step("Eradicate", "High", "Remove illicit grants and credentials", "Remove unapproved OAuth grants, app-role assignments, secrets, and certificates. Rotate any legitimate downstream credentials that may have been exposed.", "Entra admin center → App registrations"),
			step("Recover", "Standard", "Restore least privilege", "If the app is legitimate, re-enable only the reviewed permissions and credentials needed for its documented function, with a named owner and expiration.", "Detection Rules → review app-change coverage"),
			step("Validate", "Standard", "Confirm access has stopped", "Verify the service principal can no longer obtain unauthorized access and that no replacement credential, consent, or related service principal was created.", "Raw Event Explorer → monitor application changes"),
		},
		CompletionCriteria: []string{"The application has a verified business owner and publisher, or is disabled.", "Every consent grant, app role, secret, and certificate is reviewed.", "Unauthorized access is revoked and affected credentials are rotated.", "Follow-up audit and sign-in activity shows no replacement persistence."},
	}
}

func privilegePlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Privilege or membership change",
		Summary:  "Verify the change record and rapidly remove unauthorized privilege while preserving access needed for investigation.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Remove unauthorized privilege", "Confirm the requested role, owner, member, or guest assignment. If unapproved, reverse only that assignment and block the initiating identity when compromise is suspected.", "Users or Groups → run the matching What-If action"),
			step("Investigate", "High", "Review the actor and approval trail", "Validate the actor, source IP, authentication context, target object, previous membership, and help-desk or change ticket. Pay special attention to guests and privileged roles.", "Raw Event Explorer → search actor and target"),
			step("Investigate", "High", "Trace follow-on administration", "Review every directory, application, mailbox, and sharing change made by the actor after privilege was obtained, including changes across other managed tenants.", "Security Operations → filter by actor"),
			step("Recover", "Standard", "Restore approved membership", "Reapply only documented least-privilege access with an accountable owner and time limit where supported.", "Groups → verify owners and members"),
			step("Validate", "Standard", "Confirm effective privilege", "Verify the unauthorized member or owner no longer has direct, nested, eligible, or application-derived access and monitor for reassignment.", "Global Reports → Privileged roles"),
		},
		CompletionCriteria: []string{"The assignment is tied to an approved change or has been reversed.", "The initiating identity and authentication context are verified.", "Follow-on changes made with the privilege are reviewed.", "Effective membership and ownership now match least privilege."},
	}
}

func dataAccessPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "SharePoint or OneDrive data access",
		Summary:  "Limit ongoing exposure, preserve evidence, and determine exactly which content and recipients were affected.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Remove unauthorized sharing or access", "Disable suspicious anonymous or specific-people links and remove unapproved direct grants. If the actor is untrusted, contain that identity as well.", "SharePoint → investigate access and run What-If"),
			step("Investigate", "High", "Scope affected content", "Identify sites, libraries, files, recipients, downloads, deletions, sharing links, client IPs, and the earliest observed activity. Preserve the audit trail before changing additional permissions.", "Raw Event Explorer → search actor, site, and IP"),
			step("Investigate", "High", "Check inherited and group access", "Determine whether access came from a direct grant, link, site membership, group membership, or inheritance so the correct control is changed without causing unnecessary outages.", "SharePoint → Share Detective"),
			step("Recover", "Standard", "Restore content and approved access", "Recover deleted content where possible, rotate exposed secrets contained in affected files, and restore only verified permissions and sharing settings.", "SharePoint → site detail"),
			step("Validate", "Standard", "Confirm exposure is closed", "Retest links and effective permissions, confirm external recipients no longer have access, and monitor for renewed downloads, deletions, or sharing.", "SharePoint → refresh investigation"),
		},
		CompletionCriteria: []string{"Every affected site, file, link, and recipient is documented.", "Unauthorized direct, group, inherited, and link-based access is removed.", "Deleted content and exposed secrets have been addressed.", "Effective-access validation shows the exposure is closed."},
	}
}

func controlChangePlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Security control change",
		Summary:  "Restore the last approved protection carefully, then determine whether the control change concealed or enabled other activity.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Restore approved protection", "Compare the current configuration with the last approved state. Re-enable or restore the affected Conditional Access or audit control after checking for an emergency access requirement and avoiding administrator lockout.", "Tenant detail → review control state"),
			step("Investigate", "High", "Validate the actor and change window", "Confirm the change ticket, actor, IP, authentication context, exclusions, targets, and exact before/after values. Treat unexplained audit disablement as possible defense evasion.", "Raw Event Explorer → search actor and policy"),
			step("Investigate", "High", "Review activity during reduced coverage", "Search for sign-ins, privilege changes, app consents, mailbox changes, and data access from the control change until protection and ingestion were verified.", "Security Operations → review correlated incidents"),
			step("Recover", "Standard", "Harden and document the control", "Remove unapproved exclusions, test the policy with a limited scope where possible, retain emergency access, and record the approved configuration owner.", "Global Reports → Conditional Access exclusions"),
			step("Validate", "Standard", "Verify enforcement and telemetry", "Confirm the control applies to intended users and apps and that new audit events are arriving in RTM before resolving the incident.", "Security Operations → Connector Health"),
		},
		CompletionCriteria: []string{"The current control matches an approved configuration.", "The actor and reason for the change are verified.", "Activity during the reduced-protection window is reviewed.", "Enforcement and RTM audit ingestion are both healthy."},
	}
}

func phishingPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Phishing campaign",
		Summary:  "Contain the messages and any compromised recipients, then search for the same campaign across the tenant.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "Immediate", "Stop message exposure", "Quarantine or remove confirmed malicious messages using the licensed Microsoft security tooling available to the tenant, and block known malicious senders, URLs, or domains where appropriate.", "Open in Defender when available"),
			step("Investigate", "High", "Find all recipients and interactions", "Search for matching sender, subject, URL, attachment, network indicators, deliveries, clicks, replies, and forwarding. Identify users who entered credentials or approved MFA prompts.", "Raw Event Explorer → search campaign indicators"),
			step("Contain", "Immediate", "Secure affected users", "For any recipient with suspected interaction, block sign-in, revoke sessions, reset the password, remove unknown MFA methods, and review mailbox rules and app consents.", "Users → Revoke user access (What-If)"),
			step("Recover", "Standard", "Restore trusted communications", "Release only verified false positives, notify affected users through a trusted channel, and restore accounts after identity and device checks complete.", "Users → review account status"),
			step("Validate", "Standard", "Monitor campaign indicators", "Confirm no matching messages remain accessible and no new sign-ins, rules, consents, or deliveries appear for the identified indicators.", "Security Operations → repeat indicator search"),
		},
		CompletionCriteria: []string{"All known message copies, recipients, and interactions are scoped.", "Interacting users are contained and investigated.", "Malicious indicators are blocked where supported.", "Follow-up searches show no continuing delivery or account activity."},
	}
}

func auditEvidencePlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Audit and investigation activity",
		Summary:  "Audit searches can be legitimate SOC work or an attempt to discover monitoring coverage; verify purpose and protect exported evidence.",
		Steps: []model.SecurityRemediationStep{
			step("Investigate", "High", "Verify the investigator and case", "Confirm the actor, investigation or legal-hold case, search scope, time range, query, export destination, and approval. Contact the named investigator through a trusted channel.", "Audit Logs → verify the RTM operator trail"),
			step("Contain", "High", "Protect evidence and credentials", "If the search is unauthorized, contain the initiating identity and restrict access to any exported results. Preserve the search identifiers and timestamps before changing access.", "Users → Revoke user access (What-If)"),
			step("Investigate", "High", "Determine what was viewed or exported", "Review follow-on audit searches, compliance searches, exports, downloads, deletions, and sharing activity by the actor and from the same client IP.", "Raw Event Explorer → search actor and client IP"),
			step("Recover", "Standard", "Restore least-privilege investigation access", "Remove unauthorized role assignments or sessions and retain only the investigation permissions required for approved responders.", "Global Reports → Privileged roles"),
			step("Validate", "Standard", "Confirm monitoring and evidence integrity", "Verify unified auditing and RTM ingestion remain healthy, exported evidence is accounted for, and no audit configuration was weakened.", "Security Operations → Connector Health"),
		},
		CompletionCriteria: []string{"The search maps to an approved case and investigator, or the actor is contained.", "Search scope and exported evidence are accounted for.", "Related privilege, export, download, and sharing activity is reviewed.", "Unified auditing and RTM ingestion remain healthy."},
	}
}

func accountChangePlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "Account lifecycle change",
		Summary:  "Confirm the identity lifecycle request and distinguish an approved help-desk action from attacker-driven account manipulation.",
		Steps: []model.SecurityRemediationStep{
			step("Contain", "High", "Protect the affected account", "If the creation, deletion, enablement, disablement, invitation, or password change is unapproved, block the affected account and contain the initiating identity while the source of authority is checked.", "Users → Block sign-in or Revoke user access (What-If)"),
			step("Investigate", "High", "Verify the request and actor", "Confirm the sponsor or help-desk ticket, actor, IP, target account, source of authority, assigned groups, roles, licenses, authentication methods, and actions performed after the change.", "Raw Event Explorer → search actor and user"),
			step("Eradicate", "High", "Reverse unauthorized state", "Remove unauthorized guest or cloud accounts, restore approved accounts through the authoritative identity process, and remove privileges or MFA methods created during the incident.", "Users and Groups → use approved What-If actions"),
			step("Recover", "Standard", "Re-establish the trusted identity", "Issue fresh credentials through a verified channel and restore only the access required for the user's current role.", "Users → review account and license state"),
			step("Validate", "Standard", "Confirm lifecycle consistency", "Verify Entra, hybrid directory, group, license, and mailbox state agree with the approved identity record and monitor for repeated changes.", "Users → refresh directory inventory"),
		},
		CompletionCriteria: []string{"The lifecycle action has a verified sponsor or change record.", "The actor and source-of-authority path are understood.", "Unauthorized state and follow-on access are removed.", "Directory and application state match the approved identity record."},
	}
}

func genericPlan() model.SecurityRemediationPlan {
	return model.SecurityRemediationPlan{
		Category: "General Microsoft 365 investigation",
		Summary:  "Verify the activity, contain affected identities or resources when risk is credible, and document evidence before changing tenant state.",
		Steps: []model.SecurityRemediationStep{
			step("Investigate", "High", "Confirm the event and business context", "Validate the actor, target, time, client IP, result, exact change, and associated approval record. Contact the owner through a trusted channel.", "Raw Event Explorer → search incident entities"),
			step("Contain", "High", "Limit credible ongoing risk", "If the activity is unauthorized or cannot be promptly verified, block affected identities or remove the narrowest unsafe permission or configuration through the normal What-If workflow.", "Use the relevant tenant tool → What-If"),
			step("Investigate", "High", "Determine scope", "Review related sign-ins, directory changes, mailbox activity, application grants, and file access before and after the event. Preserve identifiers and timestamps.", "Security Operations → filter related incidents"),
			step("Recover", "Standard", "Restore the approved state", "Remove persistence, rotate exposed credentials, and restore only verified access or configuration.", "Use the relevant tenant inventory"),
			step("Validate", "Standard", "Prove the response worked", "Refresh the affected inventory and repeat the evidence search. Resolve only after the owner confirms expected behavior and monitoring shows no recurrence.", "Raw Event Explorer → repeat the evidence search"),
		},
		CompletionCriteria: []string{"The actor, target, and business purpose are verified.", "Credible ongoing access has been contained.", "Related activity and persistence paths are reviewed.", "The approved state is restored and follow-up monitoring is clean."},
	}
}
