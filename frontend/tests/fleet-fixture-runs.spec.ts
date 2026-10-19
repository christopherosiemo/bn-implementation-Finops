import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";

type Run = components["schemas"]["FleetFixtureRun"];
const row = (changes: Partial<Run> = {}): Run => ({
  id: "journal-unknown",
  proposal_id: "proposal-one",
  workload_id: "workload-one",
  created_at: "2026-10-19T12:00:00Z",
  realm: {
    kind: "ISOLATED_FIXTURE",
    fixture_id: "installed-fixture",
    generation: "generation-one",
    model_sha256: "a".repeat(64),
  },
  segment: "segment-one",
  record_count: 5,
  global_count: "18446744073709551615",
  head_sha256: "b".repeat(64),
  owned_effect_count: 1,
  pending_phase: "UNKNOWN",
  forward_aborted: false,
  recovery_only: false,
  obligation_released: false,
  customer_execution_authorized: false,
  financial_disposition: "UNAVAILABLE",
  status: "RECONCILING",
  reason_codes: ["TERMINAL_RECEIPT_REQUIRED"],
  ...changes,
});

// All API and OIDC routes are mocked. These tests assert presentation only,
// not PostgreSQL durability, authenticated human approval or native effects.
async function open(
  page: Page,
  options: { rows?: Run[]; error?: number } = {},
) {
  const calls: string[] = [],
    writes: string[] = [];
  let firstPages = 0;
  await page.addInitScript(() => {
    sessionStorage.setItem("finops.oidc.state", "presentation-state");
    sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier");
  });
  await page.route("**/.well-known/openid-configuration", (route) =>
    route.fulfill({
      json: {
        authorization_endpoint: "http://127.0.0.1/unused",
        token_endpoint: `${new URL(page.url()).origin}/__runs-token`,
      },
    }),
  );
  await page.route("**/__runs-token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", (route) => {
    const request = route.request(),
      url = new URL(request.url());
    calls.push(url.pathname + url.search);
    if (request.method() !== "GET") {
      writes.push(request.method());
      return route.fulfill({
        status: 405,
        json: { error: "presentation is read-only" },
      });
    }
    if (options.error)
      return route.fulfill({
        status: options.error,
        json: {
          error: "AUTHORIZATION_REQUIRED",
          message: "The current session cannot read fixture journals.",
        },
      });
    if (url.pathname !== "/v1/fleet-fixture-proposals/proposal-one/runs")
      return route.fulfill({
        status: 404,
        json: { error: "unknown fixture route" },
      });
    const rows = options.rows ?? [row()];
    if (!url.searchParams.has("cursor")) firstPages++;
    return route.fulfill({
      json: {
        items: url.searchParams.has("cursor")
          ? rows.slice(1)
          : rows.slice(0, 1),
        next_cursor:
          rows.length > 1 && !url.searchParams.has("cursor")
            ? "opaque-run-next"
            : null,
        status: "OBSERVABLE",
        reason_codes: [],
      },
    });
  });
  await page.goto(
    "/tests/fixtures/fleet-fixture-runs.html?code=presentation&state=presentation-state",
  );
  await expect(
    page.getByRole("heading", { name: "Execution & owned recovery" }),
  ).toBeVisible();
  return { calls, writes, firstPages: () => firstPages };
}

test("empty private runtime is distinct from completed execution", async ({
  page,
}) => {
  const observed = await open(page, { rows: [] });
  await expect(
    page.getByText(
      "The private runtime has not issued a journal for this proposal. Customer execution is disabled.",
    ),
  ).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
  expect(observed.writes).toEqual([]);
});

test("unknown retains ownership and exact event integer without a completion claim", async ({
  page,
}) => {
  const observed = await open(page);
  await expect(page.getByText("Reconciling", { exact: true })).toBeVisible();
  await expect(page.getByText("Unknown", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Restoration ownership retained", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Terminal receipt required", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/18446744073709551615 recorded events/),
  ).toBeVisible();
  await expect(
    page.getByText("Verified savings: unavailable", { exact: true }),
  ).toBeVisible();
  expect(observed.writes).toEqual([]);
});

test("required recovery and recovered disqualified history remain separately visible through cursor pages", async ({
  page,
}) => {
  const observed = await open(page, {
    rows: [
      row({
        status: "RECOVERY_REQUIRED",
        pending_phase: "UNKNOWN",
        reason_codes: ["OWNED_RESTORATION_REQUIRED"],
        forward_aborted: true,
        financial_disposition: "DISQUALIFIED",
      }),
      row({
        id: "journal-recovered",
        status: "RECOVERED",
        owned_effect_count: 0,
        pending_phase: null,
        obligation_released: true,
        forward_aborted: true,
        recovery_only: true,
        financial_disposition: "DISQUALIFIED",
        reason_codes: [],
      }),
    ],
  });
  await expect(
    page.getByText("Recovery required", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Load more persisted fixture runs" })
    .click();
  await expect(page.getByText("Recovered", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Native duties resolved", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Disqualified", { exact: true })).toHaveCount(2);
  await expect(
    page.getByText(
      "Forward progress is permanently aborted. This run cannot establish positive verified savings.",
    ),
  ).toHaveCount(2);
  expect(
    observed.calls.some((path) => path.endsWith("cursor=opaque-run-next")),
  ).toBe(true);
  expect(observed.writes).toEqual([]);
});

test("refresh reloads the scoped first page with no execution mutation", async ({
  page,
}) => {
  const observed = await open(page);
  await expect(page.getByText("Reconciling", { exact: true })).toBeVisible();
  const refreshed = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname ===
      "/v1/fleet-fixture-proposals/proposal-one/runs",
  );
  await page
    .getByRole("button", { name: "Refresh persisted fixture runs" })
    .click();
  await refreshed;
  await expect(page.getByText("Reconciling", { exact: true })).toBeVisible();
  expect(observed.firstPages()).toBe(2);
  expect(observed.writes).toEqual([]);
});

test("unauthorized reads display an error rather than an empty or recovered journal", async ({
  page,
}) => {
  const observed = await open(page, { error: 401 });
  await expect(page.getByRole("alert")).toContainText(
    "The current session cannot read fixture journals.",
  );
  await expect(
    page.getByText("Native duties resolved", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByRole("table")).toHaveCount(0);
  expect(observed.writes).toEqual([]);
});
