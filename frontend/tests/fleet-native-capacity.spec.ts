import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";

// Presentation doubles only. The connected lab separately exercises native
// Prometheus, archive, model, restricted PostgreSQL and worker publication.
const stamp = "2026-10-19T12:00:00Z",
  hash = "a".repeat(64);
const pin = {
  receipt_id: "receipt",
  revision_id: "revision",
  receipt_version_id: "rv1",
  revision_version_id: "rv2",
  raw_sha256: hash,
};
const selection = {
  safety_profile: { id: "profile", version: 3, sha256: hash },
  groups: {
    old_configuration_proposal: { id: "proposal-original", sha256: hash },
    candidate_configuration_proposal: {
      id: "proposal-candidate",
      sha256: hash,
    },
  },
};
const candidate = {
  id: "lt-candidate",
  version: "9007199254740993",
  instance_type: "m6i.large",
  image_id: "ami-12345678",
  definition_sha256: hash,
  source_pin: pin,
  reason_codes: [],
};
function scope(mode: "observed" | "missing" | "empty" = "observed") {
  return {
    selection,
    snapshot_sha256: hash,
    population_status: mode === "missing" ? "UNAVAILABLE" : "OBSERVED_POINT",
    observed_at: mode === "missing" ? "0001-01-01T00:00:00Z" : stamp,
    membership_pins: [pin],
    current_member_ids: mode === "observed" ? ["i-12345678", "i-87654321"] : [],
  };
}
function model() {
  const quantile = {
    lower: "16320875724.8",
    upper: "16320875724.8",
    status: "OBSERVED",
  };
  return {
    model_version: "capacity-weekday-block-v2",
    metrics: [
      {
        name: "memory",
        unit: "bytes",
        statistic: "RAW_SAMPLE",
        coverage_ppm: 1000000,
        observed_intervals: 4032,
        expected_intervals: 4032,
        missing_intervals: 0,
        unknown_seconds: "0",
        observed_quantiles: { p95: quantile, p99: quantile },
        quantile_method: "NEAREST_RANK_OBSERVED_SAMPLES",
        denominator: { value: "17179869184", unit: "bytes" },
      },
    ],
    forecasts: [],
    candidates: [
      {
        id: "m6i.large",
        count: 1,
        status: "BLOCKED",
        reason_codes: [
          "MEMORY_P99_ROLLBACK_LIMIT",
          "COMMITMENT_COMPATIBILITY_UNPROVEN",
        ],
        future_risk: { status: "UNCALIBRATED" },
        checks: [
          {
            dimension: "memory",
            candidate_capacity: "8589934592",
            unit: "bytes",
            required_with_reserve: "21217138442.24",
            reserve_above_forecast_ppm: 300000,
            unused_capacity_ppm: 0,
            observed_p95_utilization_ppm: 1900000,
            p95_planning_limit_ppm: 750000,
            projected_p99_utilization_ppm: 1900000,
            p99_rollback_limit_ppm: 900000,
            observed_capacity_breach_ppm: 1000000,
            status: "FAIL",
          },
        ],
      },
    ],
    model_assumptions: [
      "Observed samples do not prove completed business work.",
    ],
    evidence_refs: [],
    assessment_hash: hash,
  };
}
async function open(
  page: Page,
  options: {
    queued?: boolean;
    mode?: "observed" | "missing" | "empty";
    noProfile?: boolean;
    failure?: number;
  } = {},
) {
  let pending = options.queued ?? false;
  let profileVersion = 3;
  const reads: string[] = [],
    writes: { body: unknown; version?: string; idempotency?: string }[] = [];
  const summary = (id: string, instance: string, evaluated: boolean) => ({
    schema_version: "1",
    id,
    request_id: "batch-one",
    instance_id: instance,
    sha256: hash,
    status: evaluated ? "BLOCKED" : "UNAVAILABLE",
    model_evaluated: evaluated,
    capacity_suitable: evaluated ? false : null,
    reason_codes: evaluated
      ? ["COMMITMENT_COMPATIBILITY_UNPROVEN"]
      : ["MEMORY_EVIDENCE_MISSING"],
    created_at: stamp,
  });
  const row = () => ({
    schema_version: "1",
    id: "batch-one",
    version: 1,
    workload_id: "workload-one",
    creator_id: "owner",
    created_at: stamp,
    selection: {
      ...selection,
      safety_profile: { ...selection.safety_profile, version: profileVersion },
    },
    status: pending ? "QUEUED" : "ASSESSED",
    execution_authorized: false,
    verified_saving: null,
    scope: pending
      ? null
      : {
          schema_version: "1",
          request_id: "batch-one",
          scope: scope(options.mode),
          candidate_template: candidate,
          source_pins: [pin],
          reason_codes: [],
          execution_authorized: false,
          verified_saving: null,
        },
    batch: pending
      ? null
      : {
          schema_version: "1",
          scope: scope(options.mode),
          members: [],
          coverage:
            options.mode === "missing"
              ? "UNAVAILABLE"
              : options.mode === "empty"
                ? "EMPTY_POINT"
                : "PARTIAL",
          status: "BLOCKED",
          reason_codes: ["GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"],
          group_capacity_authorized: false,
          completed_business_work_preserved: null,
          execution_authorized: false,
          verified_saving: null,
        },
  });
  await page.addInitScript(() => {
    sessionStorage.setItem("finops.oidc.state", "presentation-state");
    sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier");
  });
  await page.route("**/.well-known/openid-configuration", (route) =>
    route.fulfill({
      json: {
        authorization_endpoint: "http://127.0.0.1:4177/unused",
        token_endpoint: "http://127.0.0.1:4177/__capacity-token",
      },
    }),
  );
  await page.route("**/__capacity-token", (route) =>
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
    reads.push(path);
    if (path === "/v1/workloads/workload-one/fleet-native-capacity-batches") {
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
    if (path === "/v1/fleet-native-capacity-batches/batch-one")
      return reply(row());
    if (path === "/v1/fleet-native-capacity-batches/batch-one/members")
      return reply({
        items: options.mode
          ? []
          : url.searchParams.has("cursor")
            ? [summary("member-two", "i-87654321", false)]
            : [summary("member-one", "i-12345678", true)],
        next_cursor:
          options.mode || url.searchParams.has("cursor")
            ? null
            : "opaque-member-page",
      });
    if (path === "/v1/fleet-native-capacity-members/member-one")
      return reply({
        ...summary("member-one", "i-12345678", true),
        kind: "FLEET_NATIVE_CAPACITY_MEMBER_V1",
        writer_role: "finops_group_capacity",
        member: {
          schema_version: "1",
          id: "member-one",
          batch_id: "batch-one",
          scope: scope(),
          instance_id: "i-12345678",
          observed_at: stamp,
          resource_id: "resource-one",
          binding: {
            provider_resource_id: "i-12345678",
            account_id: "111122223333",
            region: "eu-west-1",
          },
          candidate_template: candidate,
          telemetry: null,
          hardware: null,
          model_evaluated: true,
          model_evaluation: model(),
          capacity_suitable: false,
          status: "BLOCKED",
          reason_codes: ["MEMORY_P99_ROLLBACK_LIMIT"],
          demand_meaning: "REQUEST_THROUGHPUT_PROXY",
        },
      });
    if (path === "/v1/workloads/workload-one/safety-profiles")
      return reply({
        version: options.noProfile ? 0 : profileVersion,
        latest: options.noProfile
          ? null
          : { id: "profile", version: profileVersion },
        items: [],
        next_cursor: null,
      });
    if (path === "/v1/fleet-history-registrations")
      return reply({
        items: ["original", "candidate"].map((id) => ({
          id,
          version: 1,
          registration: {
            fleet_id: id,
            asg_arn: `arn:presentation:${id}`,
            binding: { account_id: "111122223333", region: "eu-west-1" },
          },
        })),
        next_cursor: null,
      });
    const proposal =
      /^\/v1\/fleet-history-registrations\/(original|candidate)\/configuration-proposals$/.exec(
        path,
      );
    if (proposal)
      return reply({
        items: [
          {
            id: `proposal-${proposal[1]}`,
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
    "/tests/fixtures/fleet-native-capacity.html?code=presentation&state=presentation-state",
  );
  expect(reads).toEqual([]);
  await page.getByText("Native fleet member capacity", { exact: true }).click();
  await expect(
    page.getByRole("region", {
      name: "Fleet capacity batch history",
      exact: true,
    }),
  ).toBeVisible();
  return {
    reads,
    writes,
    complete: () => {
      pending = false;
    },
    acceptNewProfile: () => {
      options.failure = undefined;
      profileVersion = 4;
    },
  };
}
async function selectGroups(page: Page) {
  await page
    .getByRole("button", {
      name: "Evaluate fleet member capacity",
      exact: true,
    })
    .click();
  for (const side of ["original", "candidate"]) {
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
async function inspect(page: Page) {
  await page
    .getByRole("button", {
      name: "Inspect capacity batch batch-one",
      exact: true,
    })
    .click();
  return page.getByRole("region", {
    name: "Selected fleet capacity batch",
    exact: true,
  });
}

test("member pages are scoped and lazy; high memory remains blocked with exact candidate version", async ({
  page,
}) => {
  const fixture = await open(page);
  expect(
    fixture.reads.some((path) => path.startsWith("/v1/fleet-native-capacity-")),
  ).toBe(false);
  const detail = await inspect(page);
  await expect(detail).toContainText("2 members observed");
  expect(fixture.reads).not.toContain(
    "/v1/fleet-native-capacity-members/member-one",
  );
  await page
    .getByRole("button", {
      name: "Load more fleet capacity members",
      exact: true,
    })
    .click();
  await expect(
    detail.getByRole("region", { name: "Fleet member capacity summaries" }),
  ).toContainText("i-87654321");
  await page
    .getByRole("button", { name: "Inspect member i-12345678", exact: true })
    .click();
  const member = page.getByRole("region", {
    name: "Selected fleet member capacity evidence",
    exact: true,
  });
  await expect(member).toContainText(
    "Complete candidate suitability: not established",
  );
  await member
    .getByText("Member source references & candidate configuration", {
      exact: true,
    })
    .click();
  await expect(member).toContainText("9007199254740993");
  await member
    .getByText("Inspect member observations, forecasts & physical checks", {
      exact: true,
    })
    .click();
  await member.getByText("m6i.large × 1 · Blocked", { exact: true }).click();
  await expect(
    member.getByRole("region", {
      name: "Physical planning checks for m6i.large",
    }),
  ).toContainText("Fail");
  await expect(member).toContainText("Execution disabled");
  await expect(page.locator("html")).toHaveJSProperty(
    "scrollWidth",
    await page.locator("html").evaluate((element) => element.clientWidth),
  );
  await page.screenshot({
    path: "../work/fleet-native-capacity-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator("html")).toHaveJSProperty(
    "scrollWidth",
    await page.locator("html").evaluate((element) => element.clientWidth),
  );
  await page.screenshot({
    path: "../work/fleet-native-capacity-mobile.png",
    fullPage: true,
  });
});

for (const mode of ["missing", "empty"] as const)
  test(`${mode} membership is displayed without manufacturing population`, async ({
    page,
  }) => {
    await open(page, { mode });
    const detail = await inspect(page);
    await expect(detail).toContainText(
      mode === "missing"
        ? "Original membership: unavailable"
        : "0 members observed",
    );
    await expect(detail).not.toContainText("0001");
    await expect(detail).toContainText("Verified savings: unavailable", {
      ignoreCase: true,
    });
  });

test("request sends only proposal IDs with profile revision and refreshes persisted queued result", async ({
  page,
}) => {
  const fixture = await open(page, { queued: true });
  await selectGroups(page);
  await page
    .getByRole("button", {
      name: "Request fleet member evaluation",
      exact: true,
    })
    .click();
  await expect(
    page.getByText("Queued for the capacity worker.", { exact: false }),
  ).toBeVisible();
  expect(fixture.writes).toHaveLength(1);
  expect(fixture.writes[0].body).toEqual({
    old_configuration_proposal_id: "proposal-original",
    candidate_configuration_proposal_id: "proposal-candidate",
  });
  expect(fixture.writes[0].version).toBe('"3"');
  expect(fixture.writes[0].idempotency).toBeTruthy();
  fixture.complete();
  await page
    .getByRole("button", {
      name: "Refresh selected capacity batch",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("region", {
      name: "Selected fleet capacity batch",
      exact: true,
    }),
  ).toContainText("2 members observed");
});

test("missing profile prevents a request", async ({ page }) => {
  const fixture = await open(page, { noProfile: true });
  await selectGroups(page);
  await expect(
    page.getByRole("button", {
      name: "Request fleet member evaluation",
      exact: true,
    }),
  ).toBeDisabled();
  expect(fixture.writes).toHaveLength(0);
});

test("stale profile conflict remains visible without manufacturing a successful result", async ({
  page,
}) => {
  const fixture = await open(page, { queued: true, failure: 412 });
  await selectGroups(page);
  await page
    .getByRole("button", {
      name: "Request fleet member evaluation",
      exact: true,
    })
    .click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "The safety profile revision changed" }),
  ).toContainText("The safety profile revision changed");
  await expect(page.getByRole("dialog")).toBeVisible();
  expect(fixture.writes).toHaveLength(1);
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText(
    "Request could not be confirmed",
  );
  fixture.acceptNewProfile();
  await page
    .getByRole("button", { name: "Refresh safety profile", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Safety profile revision 4",
  );
  await page
    .getByRole("button", {
      name: "Request fleet member evaluation",
      exact: true,
    })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(fixture.writes).toHaveLength(2);
  expect(fixture.writes[1].version).toBe('"4"');
  expect(fixture.writes[1].idempotency).not.toBe(fixture.writes[0].idempotency);
});
