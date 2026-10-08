import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";

import {
  DOCUMENTATION_GUIDES,
  DOCUMENTATION_SECTION_ORDER,
  MICROSOFT_PERMISSION_REFERENCE,
  documentationGuideSearchText,
} from "../src/features/documentation/documentationContent.ts";

test("documentation guides have stable unique deep links", () => {
  const slugs = DOCUMENTATION_GUIDES.map((guide) => guide.slug);
  assert.equal(new Set(slugs).size, slugs.length);

  for (const guide of DOCUMENTATION_GUIDES) {
    const headingIds = guide.blocks.flatMap((block) =>
      block.type === "heading" ? [block.id] : [],
    );
    assert.equal(new Set(headingIds).size, headingIds.length, guide.slug);
  }
});

test("documentation has a visible setup section and complete Microsoft permission guide", () => {
  const sections = new Set(DOCUMENTATION_GUIDES.map((guide) => guide.section));
  for (const section of DOCUMENTATION_SECTION_ORDER) assert.equal(sections.has(section), true, section);

  const setup = DOCUMENTATION_GUIDES.find((guide) => guide.slug === "microsoft-365-setup");
  assert.ok(setup);
  assert.equal(setup.section, "Setup");
  const documentedRows = setup.blocks
    .filter((block) => block.type === "table")
    .reduce((total, block) => total + block.rows.length, 0);
  assert.equal(documentedRows, MICROSOFT_PERMISSION_REFERENCE.length);
  const setupSearchText = documentationGuideSearchText(setup);

  const keys = MICROSOFT_PERMISSION_REFERENCE.map(
    (permission) => `${permission.resource}|${permission.permission}|${permission.authorization}`,
  );
  assert.equal(new Set(keys).size, keys.length);
  for (const expected of [
    "Microsoft Graph|AuditLog.Read.All|Application",
    "Office 365 Management APIs|ActivityFeed.Read|Application",
    "Microsoft Graph|SecurityIncident.Read.All|Application",
    "Microsoft Graph|User.Read.All|Application",
    "Microsoft Graph|Group.Read.All|Application",
    "Microsoft Graph|GroupMember.Read.All|Application",
    "Microsoft Graph|RoleManagement.Read.Directory|Application",
    "Microsoft Graph|Policy.Read.All|Application",
    "Microsoft Graph|Application.Read.All|Application",
    "Microsoft Graph|User.ReadWrite.All|Application",
    "Microsoft Graph|GroupMember.ReadWrite.All|Application",
    "Microsoft Graph|Organization.Read.All|Application",
    "Microsoft Graph|Reports.Read.All|Application",
    "Microsoft Graph|MailboxSettings.ReadWrite|Application",
    "Office 365 Exchange Online|Exchange.ManageAsAppV2|Application",
    "Exchange Online|Recipient Management|Exchange RBAC",
    "Microsoft Graph|RoleManagement.ReadWrite.Exchange|Delegated (temporary)",
    "Microsoft Graph|Sites.Read.All|Application",
    "Microsoft Graph|Sites.ReadWrite.All|Application",
    "Microsoft Graph|Sites.FullControl.All|Application",
    "SharePoint Online|Sites.FullControl.All|Application",
  ]) {
    assert.equal(keys.includes(expected), true, expected);
  }
  for (const permission of MICROSOFT_PERMISSION_REFERENCE) {
    assert.equal(setupSearchText.includes(permission.permission.toLowerCase()), true, permission.permission);
  }
});

test("every documentation screenshot resolves to a committed public asset", () => {
  const screenshots = DOCUMENTATION_GUIDES.flatMap((guide) =>
    guide.blocks.flatMap((block) => (block.type === "screenshot" ? [block.src] : [])),
  );

  assert.ok(screenshots.length >= 8);
  for (const screenshot of screenshots) {
    assert.match(screenshot, /^\/docs\/[a-z0-9-]+\.png$/);
    const asset = new URL(`../public${screenshot}`, import.meta.url);
    assert.equal(existsSync(asset), true, screenshot);
  }
});

test("security operations guide documents correlation, semantic deduplication, and resilient evidence handling", () => {
  const guide = DOCUMENTATION_GUIDES.find((candidate) => candidate.slug === "security-operations");
  assert.ok(guide);

  const searchText = documentationGuideSearchText(guide);
  for (const expected of [
    "attack storyline",
    "account takeover / bec",
    "privilege escalation and persistence",
    "data theft",
    "defense evasion",
    "msp administrator compromise",
    "compact queue defaults to active",
    "sort by risk, activity, or title",
    "10-second occurrence window",
    "every provider alias",
    "risk is a bounded 0–100 deterministic score",
    "retry or dashboard recovery",
  ]) {
    assert.equal(searchText.includes(expected), true, expected);
  }
});
