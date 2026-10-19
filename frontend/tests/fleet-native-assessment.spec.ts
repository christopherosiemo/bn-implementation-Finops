import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";

// Deliberate presentation doubles. Restricted PostgreSQL and native archive
// acceptance run separately; these values convey no evidence authority.
const stamp = "2026-10-19T12:00:00Z",
  hash = "a".repeat(64);
function result(difference: string | null = "0.16") {
  return {
    id: "assessment-one",
    schema_version: "1",
    observed_at: stamp,
    status: "BLOCKED",
    execution_authorized: false,
    change_plan_id: null,
    verified_saving: null,
    reason_codes: [
      "EXECUTION_AUTHORITY_NOT_GRANTED",
      "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE",
    ],
    capacity: {
      status: "PARTIAL",
      members: [
        {
          instance_id: "i-12345678",
          resource_id: "resource-one",
          result_id: "capacity-one",
          status: "BLOCKED",
          demand_meaning: "REQUEST_THROUGHPUT_PROXY",
        },
      ],
      missing_instance_ids: ["i-87654321"],
      historical_membership: "INTERVAL_OWNERSHIP_UNPROVEN",
      group_capacity_authorized: false,
      completed_business_work_preserved: null,
    },
    scenario: {
      status: difference === null ? "UNAVAILABLE" : "OBSERVED_CONDITIONAL",
      basis: "LIKE_FOR_LIKE_CURRENT_MEMBER_COUNT",
      rate_basis: "HISTORICAL_ACCOUNT_RATE_ESTIMATE",
      currency: difference === null ? null : "USD",
      member_count: 2,
      old_hourly_rate: difference === null ? null : "0.2",
      candidate_hourly_rate: difference === null ? null : "0.12",
      old_hourly_compute: difference === null ? null : "0.4",
      candidate_hourly_compute: difference === null ? null : "0.24",
      hourly_compute_difference: difference,
      contracted_avoidable_cost: null,
      estimated_saving: null,
      verified_saving: null,
      hard_spend_cap: false,
      excluded_costs: ["EBS", "NETWORK", "MIGRATION_AND_OVERLAP"],
    },
    native_rates: {
      valid_until: "2026-10-19T12:05:00Z",
      reason_codes: ["COMMITMENT_EXPOSURE_UNPROVEN"],
      snapshot_sha256: hash,
      economic_scope_sha256: hash,
      baseline: { start: "2026-10-05T00:00:00Z", end: "2026-10-19T00:00:00Z" },
      source_pins: [
        {
          receipt_id: "native-receipt",
          revision_id: "native-revision",
          receipt_version_id: "v1",
          revision_version_id: "v2",
          raw_sha256: hash,
        },
      ],
    },
  };
}
async function open(
  page: Page,
  options: {
    difference?: string | null;
    queued?: boolean;
    failure?: number;
    noProfile?: boolean;
  } = {},
) {
  const writes: { body: unknown; version?: string; idempotency?: string }[] =
    [];
  let pending = options.queued ?? false;
  const row = () => ({
    id: "request-one",
    version: 1,
    workload_id: "workload-one",
    creator_id: "finance-one",
    created_at: stamp,
    status: pending ? "QUEUED" : "ASSESSED",
    selection: {
      safety_profile: { id: "profile-one", version: 3, sha256: hash },
    },
    assessment: pending
      ? null
      : result(options.difference === undefined ? "0.16" : options.difference),
    execution_authorized: false,
    verified_saving: null,
  });
  await page.addInitScript(() => {
    sessionStorage.setItem("finops.oidc.state", "presentation-state");
    sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier");
  });
  await page.route("**/.well-known/openid-configuration", (route) =>
    route.fulfill({
      json: {
        authorization_endpoint: "http://127.0.0.1:4177/unused",
        token_endpoint: "http://127.0.0.1:4177/__native-token",
      },
    }),
  );
  await page.route("**/__native-token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const reply = (json: unknown, status = 200) =>
      route.fulfill({ json, status });
    if (path === "/v1/workloads/workload-one/fleet-native-assessments") {
      if (request.method() === "POST") {
        writes.push({
          body: request.postDataJSON(),
          version: request.headers()["if-match"],
          idempotency: request.headers()["idempotency-key"],
        });
        if (options.failure)
          return reply(
            {
              message: "The safety profile revision changed.",
              reason_code: "VERSION_CONFLICT",
            },
            options.failure,
          );
        pending = true;
        return reply(row(), 202);
      }
      return reply({ items: [row()], next_cursor: null });
    }
    if (path === "/v1/fleet-native-assessments/request-one")
      return reply(row());
    if (path === "/v1/workloads/workload-one/safety-profiles")
      return reply({
        version: options.noProfile ? 0 : 3,
        latest: options.noProfile ? null : { id: "profile-one", version: 3 },
        items: [],
        next_cursor: null,
      });
    if (path === "/v1/fleet-history-registrations")
      return reply({
        items: (url.searchParams.has("cursor")
          ? ["candidate"]
          : ["original"]
        ).map((id) => ({
          id,
          version: 1,
          registration: {
            fleet_id: id,
            asg_arn: `arn:presentation:${id}`,
            binding: { account_id: "111122223333", region: "eu-west-1" },
          },
        })),
        next_cursor: url.searchParams.has("cursor")
          ? null
          : "opaque-group-page",
      });
    const match =
      /^\/v1\/fleet-history-registrations\/(original|candidate)\/configuration-proposals$/.exec(
        path,
      );
    if (match)
      return reply({
        items: [
          {
            id: `proposal-${match[1]}`,
            as_of: stamp,
            status: "BLOCKED",
            membership_status: "INTERVAL_OWNERSHIP_UNPROVEN",
            registration_version: 1,
          },
        ],
        next_cursor: null,
      });
    return reply({ message: "Unmocked presentation request" }, 502);
  });
  await page.goto(
    "/tests/fixtures/fleet-native-assessment.html?code=presentation&state=presentation-state",
  );
  await page
    .getByText("Native fleet assessment & observed compute rates", {
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("region", {
      name: "Native fleet assessment history",
      exact: true,
    }),
  ).toBeVisible();
  return {
    writes,
    complete: () => {
      pending = false;
    },
  };
}
async function selectGroups(page: Page) {
  await page
    .getByRole("button", { name: "Compare fleet compute rates", exact: true })
    .click();
  for (const side of ["original", "candidate"]) {
    if (side === "candidate") {
      await page
        .getByRole("button", {
          name: "Load more candidate assessment groups",
          exact: true,
        })
        .click();
    }
    await page
      .getByRole("button", {
        name: `Assess ${side} group ${side}`,
        exact: true,
      })
      .click();
    await page
      .getByRole("button", {
        name: `Compare ${side} proposal proposal-${side}`,
        exact: true,
      })
      .click();
  }
}

test("observed comparison retains provenance, missing capacity and separate unavailable savings", async ({
  page,
}) => {
  await open(page);
  await page
    .getByRole("button", {
      name: "Inspect native assessment request-one",
      exact: true,
    })
    .click();
  const details = page.getByRole("region", {
    name: "Selected native fleet assessment",
    exact: true,
  });
  await expect(
    details.getByRole("row", {
      name: "Conditional hourly compute difference 0.16 USD/hour",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    details.getByRole("row", {
      name: "Verified savings Unavailable",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    details.getByText("Missing member assessments: i-87654321."),
  ).toBeVisible();
  await expect(
    details.getByText("Commitment exposure unproven", { exact: true }),
  ).toBeVisible();
  await details
    .getByText("Immutable source references", { exact: true })
    .click();
  await expect(
    details.getByText("Receipt object version v1; revision object version v2", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Local fixture evidence. Provider transports are simulated.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /approve|execute|apply/i }),
  ).toHaveCount(0);
  await page.screenshot({
    path: test.info().outputPath("native-assessment-presentation.png"),
    fullPage: true,
  });
});

for (const difference of [
  "0",
  "-0.16",
  "12345678901234567890123456.123456789012",
  null,
]) {
  test(`exact decimal comparison preserves ${difference === null ? "unknown" : difference}`, async ({
    page,
  }) => {
    await open(page, { difference });
    await page
      .getByRole("button", {
        name: "Inspect native assessment request-one",
        exact: true,
      })
      .click();
    await expect(
      page.getByRole("row", {
        name: `Conditional hourly compute difference ${difference === null ? "Unavailable" : `${difference} USD/hour`}`,
        exact: true,
      }),
    ).toBeVisible();
  });
}

test("IDs-only request binds profile revision and queued worker result is refreshed", async ({
  page,
}) => {
  const fixture = await open(page);
  await selectGroups(page);
  expect(fixture.writes).toHaveLength(0);
  await page
    .getByRole("button", {
      name: "Request native fleet assessment",
      exact: true,
    })
    .click();
  await expect(
    page.getByText(
      "Queued for the evidence worker. No analytical result is available yet.",
      { exact: true },
    ),
  ).toBeVisible();
  expect(fixture.writes).toHaveLength(1);
  expect(fixture.writes[0].body).toEqual({
    old_configuration_proposal_id: "proposal-original",
    candidate_configuration_proposal_id: "proposal-candidate",
  });
  expect(fixture.writes[0].version).toBe('"3"');
  expect(fixture.writes[0].idempotency).toMatch(/^[a-f0-9-]{36}$/);
  fixture.complete();
  await page
    .getByRole("button", { name: "Refresh selected assessment", exact: true })
    .click();
  await expect(
    page.getByRole("row", {
      name: "Conditional hourly compute difference 0.16 USD/hour",
      exact: true,
    }),
  ).toBeVisible();
});

test("stale profile response leaves the failed request visible without presenting a result", async ({
  page,
}) => {
  const fixture = await open(page, { failure: 412 });
  await selectGroups(page);
  await page
    .getByRole("button", {
      name: "Request native fleet assessment",
      exact: true,
    })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "Refresh the view and retry.",
  );
  await expect(
    page.getByRole("dialog", {
      name: "Compare observed fleet compute rates",
      exact: true,
    }),
  ).toBeVisible();
  expect(fixture.writes).toHaveLength(1);
});

test("missing profile disables request and never sends a mutation", async ({
  page,
}) => {
  const fixture = await open(page, { noProfile: true });
  await selectGroups(page);
  await expect(
    page.getByText(
      "Record a workload safety profile before requesting an assessment.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Request native fleet assessment",
      exact: true,
    }),
  ).toBeDisabled();
  expect(fixture.writes).toHaveLength(0);
});
