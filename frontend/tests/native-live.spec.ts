import { test, expect, type Page, type Response } from "@playwright/test";
import type { components } from "../src/api.generated";

function nativeSourceList(urlText: string, method: string) {
  const url = new URL(urlText);
  return (
    url.pathname === "/v1/telemetry-connections" &&
    url.searchParams.get("workload_id") === "workload-dev" &&
    method === "GET"
  );
}

async function findNativeSource(page: Page, firstPage: Response, sourceId: string) {
  expect(firstPage.status()).toBe(200);
  let sourcePage = (await firstPage.json()) as {
    items: components["schemas"]["TelemetryConnection"][];
    next_cursor: string | null;
  };
  const sources = page.getByRole("region", {
    name: "Scrollable native telemetry sources",
    exact: true,
  });
  const seenCursors = new Set<string>();
  // Every refresh resets the ID-ordered collection to page one. Await each
  // real cursor page's rendering instead of assuming the new ID is on it.
  for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
    expect(sourcePage.items.length).toBeGreaterThan(0);
    await expect(
      sources.getByRole("button", {
        name: `Inspect native telemetry ${sourcePage.items[0].id}`,
        exact: true,
      }),
    ).toBeVisible();
    if (sourcePage.items.some((item) => item.id === sourceId)) break;
    const cursor = sourcePage.next_cursor;
    expect(cursor, "Created source must appear in the scoped collection").not.toBeNull();
    expect(seenCursors.has(cursor!)).toBe(false);
    seenCursors.add(cursor!);
    const nextPage = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return (
        nativeSourceList(response.url(), response.request().method()) &&
        url.searchParams.get("cursor") === cursor
      );
    });
    await page
      .getByRole("button", {
        name: "Load more native telemetry connections",
        exact: true,
      })
      .click();
    const next = await nextPage;
    expect(next.status()).toBe(200);
    sourcePage = await next.json();
  }
  expect(sourcePage.items.some((item) => item.id === sourceId)).toBe(true);
  await expect(
    sources.getByRole("button", {
      name: `Inspect native telemetry ${sourceId}`,
      exact: true,
    }),
  ).toBeVisible();
}

test("real OIDC and UI register exact native units and inspect persisted telemetry without inventing history", async ({
  page,
}) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await page
    .getByRole("textbox", { name: /username/i })
    .fill(process.env.FINOPS_E2E_USER || "owner");
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  const [initial] = await Promise.all([
    page.waitForResponse(
      (response) => response.url().endsWith("/v1/dashboard") && response.ok(),
    ),
    page.getByRole("button", { name: "Sign In", exact: true }).click(),
  ]);
  expect(
    (await initial.json()).fixture,
    "This acceptance test is restricted to the local fixture stack.",
  ).toBe(true);
  const authorization = initial.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);

  await page.getByRole("link", { name: "Workloads & resources" }).click();
  await page
    .getByLabel("Safety requirements workload")
    .selectOption("workload-dev");
  await page
    .getByRole("button", { name: "Configure safety requirements" })
    .click();
  const requirements = page.getByRole("dialog", {
    name: "Configure workload safety requirements",
  });
  await requirements
    .getByLabel("Workload criticality")
    .selectOption("NON_PRODUCTION");
  await requirements
    .getByLabel("Workload statefulness")
    .selectOption("UNKNOWN");
  await requirements
    .getByLabel("High seasonality requires at least 90 complete days")
    .uncheck();
  await requirements.getByLabel("Safety policy timezone").fill("Europe/London");
  for (const [label, value] of Object.entries({
    "Minimum healthy replicas": "1",
    "Minimum healthy zones": "1",
    "CPU unused capacity (ppm)": "300000",
    "Memory unused capacity (ppm)": "250000",
    "Reserve above forecast (ppm)": "300000",
    "CPU p99 rollback ceiling (ppm)": "850000",
    "Memory p99 rollback ceiling (ppm)": "900000",
    "Recovery time target (seconds)": "300",
    "Maximum simultaneous disruptive change (ppm)": "250000",
    "VM change cooldown (seconds)": "86400",
  }))
    await requirements.getByLabel(label, { exact: true }).fill(value);
  await requirements.getByLabel("Declare a specific RPO requirement").uncheck();
  await requirements
    .getByRole("button", { name: "Save safety requirements" })
    .click();
  await expect(requirements).not.toBeVisible();
  const assessment = page.getByRole("region", {
    name: /Safety assessment for/,
  });
  await expect(assessment).toContainText("Not authorized by this view");
  await expect(assessment).toContainText("Recovery evidence required");

  await page.getByRole("link", { name: "Connections & quality" }).click();
  await page
    .getByLabel("Native telemetry workload")
    .selectOption("workload-dev");
  await page.getByRole("button", { name: "Register native source" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Register native telemetry connection",
  });
  await dialog
    .getByLabel("Telemetry resource")
    .selectOption("resource-dev-api");
  await dialog
    .getByLabel("Approved Prometheus read binding ID")
    .fill("fixture-prometheus-dev-api");
  await dialog
    .getByRole("button", { name: "Add metric definition", exact: true })
    .click();
  await dialog.getByLabel("Canonical metric 1").selectOption("request_count");
  await dialog
    .getByLabel("Native metric name 1")
    .fill("finops_gateway_requests_total");
  await dialog
    .getByLabel("Definition ID 1")
    .fill(`ui-served-requests-${Date.now()}`);
  await dialog.getByLabel("Definition version 1").fill("1");
  await dialog.getByLabel("Metric unit 1").fill("requests");
  await dialog.getByLabel("Expected cadence 1 (seconds)").fill("15");
  await dialog.getByLabel("Maximum gap 1 (seconds)").fill("30");
  await dialog
    .getByLabel("Counter epoch metric 1")
    .fill("process_start_time_seconds");
  const registered = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/telemetry-connections") &&
      response.request().method() === "POST",
  );
  const refreshedSources = page.waitForResponse(async (response) => {
    const url = new URL(response.url());
    const matches =
      nativeSourceList(response.url(), response.request().method()) &&
      !url.searchParams.has("cursor");
    if (!matches) return false;
    const created = await registered;
    return (
      response.request().timing().startTime >=
      created.request().timing().startTime
    );
  });
  await dialog
    .getByRole("button", { name: "Save telemetry configuration" })
    .click();
  const created = await registered;
  expect(created.status()).toBe(201);
  const source =
    (await created.json()) as components["schemas"]["TelemetryConnection"];
  expect(source.definitions[0].unit).toBe("requests");
  expect(source.binding.resource_id).toBe("resource-dev-api");
  expect(source.definitions[0].attributes.finops_resource_id).toBe(
    "resource-dev-api",
  );
  await expect(dialog).not.toBeVisible();
  await findNativeSource(page, await refreshedSources, source.id);
  await page
    .getByRole("button", { name: `Inspect native telemetry ${source.id}` })
    .click();
  const evidence = page.getByRole("dialog", {
    name: "Native telemetry evidence",
  });
  await expect(
    evidence.getByRole("region", {
      name: "Scrollable registered metric definitions",
    }),
  ).toContainText("SUM · requests");
  await evidence
    .getByRole("button", { name: "Synchronize history", exact: true })
    .click();
  const sync = evidence.getByRole("region", {
    name: "Durable native synchronization",
  });
  await expect(sync.getByText("Completed", { exact: true })).toBeVisible({
    timeout: 90_000,
  });
  await expect(sync).toContainText("observed coverage is evaluated separately");
  const evaluated = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/telemetry-connections/${source.id}/evaluate`) &&
      response.request().method() === "POST",
  );
  await evidence
    .getByRole("button", { name: "Evaluate history", exact: true })
    .click();
  const evaluatedResponse = await evaluated;
  expect(evaluatedResponse.status()).toBe(201);
  const record =
    (await evaluatedResponse.json()) as components["schemas"]["TelemetryEvaluationRecord"];
  expect(record.evaluation.status).toBe("BLOCKED");
  expect(
    record.evaluation.metrics.some((metric) => metric.coverage_ppm < 1_000_000),
  ).toBe(true);
  const evaluation = evidence.getByRole("region", {
    name: `Native evaluation ${record.id}`,
    exact: true,
  });
  await expect(evaluation).toContainText("Blocked");
  await expect(evaluation).toContainText(
    "missing observations remain unavailable",
  );
  await expect
    .poll(
      async () => {
        const response = await page.request.get(
          `/v1/telemetry-connections/${source.id}/receipts?limit=100`,
          { headers: { Authorization: authorization } },
        );
        expect(response.ok()).toBe(true);
        const pageOfReceipts =
          (await response.json()) as components["schemas"]["TelemetryReceiptPage"];
        return pageOfReceipts.items.some(
          (receipt) =>
            receipt.sample_count > 0 &&
            receipt.active_source &&
            /^[a-f0-9]{64}$/.test(receipt.canonical_hash),
        );
      },
      { timeout: 45_000 },
    )
    .toBe(true);
  await evidence
    .getByText("Assess historical capacity evidence", { exact: true })
    .click();
  const assessed = page.waitForResponse(
    (response) =>
      response.url().endsWith("/workloads/workload-dev/capacity-assessments") &&
      response.request().method() === "POST",
  );
  await evidence
    .getByRole("button", { name: "Assess capacity evidence", exact: true })
    .click();
  const capacityResponse = await assessed;
  expect(capacityResponse.status()).toBe(201);
  const capacity =
    (await capacityResponse.json()) as components["schemas"]["CapacityAssessment"];
  expect(capacity.status).toBe("BLOCKED");
  expect(capacity.execution_authorized).toBe(false);
  expect(capacity.estimated_saving).toBeNull();
  expect(capacity.verified_saving).toBeNull();
  expect(capacity.reason_codes).toContain(
    "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED",
  );
  expect(capacity.reason_codes).toContain("NATIVE_PRICE_UNAVAILABLE");
  expect(capacity.population_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(capacity.receipt_ids.length).toBeGreaterThan(0);
  expect(capacity.source_refs.map((ref) => ref.receipt_id)).toEqual(
    capacity.receipt_ids,
  );
  const capacityView = evidence.getByRole("region", {
    name: `Capacity assessment ${capacity.id}`,
    exact: true,
  });
  await expect(capacityView).toContainText("Not authorized by this assessment");
  await expect(capacityView).toContainText("Unavailable / Unavailable");
  await evidence.getByRole("button", { name: "Close dialog" }).click();
  const refreshRequest = page.waitForRequest(
    (request) =>
      nativeSourceList(request.url(), request.method()) &&
      !new URL(request.url()).searchParams.has("cursor"),
  );
  await page.getByRole("button", { name: "Refresh native sources" }).click();
  const refreshedAgain = await (await refreshRequest).response();
  expect(refreshedAgain).not.toBeNull();
  await findNativeSource(page, refreshedAgain!, source.id);

  // Continue the same real evidence journey. A declaration is configuration
  // metadata only; even a persisted proposal must remain blocked and unpriced.
  await page.getByRole("link", { name: "Workloads & resources" }).click();
  await page
    .getByLabel("Configuration authority workload")
    .selectOption("workload-dev");
  await page
    .getByLabel("Configuration authority resource")
    .selectOption("resource-dev-api");
  const authorityPanel = page
    .locator(".panel")
    .filter({
      has: page.getByRole("heading", {
        name: "Configuration ownership & proposal evidence",
        exact: true,
      }),
    });
  await authorityPanel
    .getByRole("button", {
      name: /^(Declare Terraform ownership|Revise ownership declaration)$/,
    })
    .click();
  const declaration = page.getByRole("dialog", {
    name: "Declare Terraform configuration authority",
  });
  for (const [label, value] of Object.entries({
    "Repository HTTPS URL":
      "https://github.com/example/fixture-infrastructure.git",
    "Declared Git branch or tag": "main",
    "Repository relative directory": "envs/development",
    "Pipeline issuer HTTPS URL": "https://token.actions.githubusercontent.com",
    "Exact pipeline machine subject":
      "repo:example/fixture-infrastructure:ref:refs/heads/main",
    "Stable pipeline identifier": ".github/workflows/deploy.yml",
    "Terraform workspace": "fixture-development",
    "Declared Terraform state lineage UUID":
      "0f5a34b0-a480-4cda-9f6a-9b205ced7937",
    "Managed Terraform resource addresses":
      'module.api["development"].aws_instance.api[0]',
  }))
    await declaration.getByLabel(label, { exact: true }).fill(value);
  await declaration.getByRole("checkbox", { name: /I acknowledge/ }).check();
  const declared = page.waitForResponse(
    (response) =>
      response
        .url()
        .endsWith("/resources/resource-dev-api/configuration-authorities") &&
      response.request().method() === "POST",
  );
  await declaration
    .getByRole("button", { name: "Save ownership declaration" })
    .click();
  const declarationResponse = await declared;
  expect(declarationResponse.status()).toBe(201);
  const authority =
    (await declarationResponse.json()) as components["schemas"]["ConfigurationAuthority"];
  expect(authority.status).toBe("DECLARED_NOT_ATTESTED");
  expect(authority.execution_authorized).toBe(false);
  expect(authority.observed_commit).toBeNull();
  expect(authority.observed_state_serial).toBeNull();
  expect(authority.binding.resource_id).toBe("resource-dev-api");
  expect(authority.binding.provider_resource_id).toBe(
    source.binding.provider_resource_id,
  );
  expect(authority.binding.resource_snapshot_hash).toMatch(/^[a-f0-9]{64}$/);
  await expect(declaration).not.toBeVisible();
  await authorityPanel
    .getByRole("button", { name: "Review proposal evidence" })
    .click();
  const proposalDialog = page.getByRole("dialog", {
    name: "Record a blocked configuration proposal",
  });
  const selection = proposalDialog.getByRole("radio", {
    name: `Select capacity assessment ${capacity.id}`,
    exact: true,
  });
  await expect(
    proposalDialog.getByRole("region", {
      name: "Scrollable capacity assessment selection",
    }),
  ).toBeVisible();
  for (
    let pageNumber = 0;
    !(await selection.count()) && pageNumber < 20;
    pageNumber++
  ) {
    const more = proposalDialog.getByRole("button", {
      name: "Load more capacity assessments for proposal",
      exact: true,
    });
    await expect(more).toBeVisible();
    const loaded = page.waitForResponse(
      (response) =>
        response
          .url()
          .includes("/workloads/workload-dev/capacity-assessments?") &&
        response.url().includes("cursor=") &&
        response.request().method() === "GET",
    );
    await more.click();
    await loaded;
    if (await more.count())
      await expect(more).toHaveAttribute("aria-busy", "false");
  }
  await selection.check();
  const proposed = page.waitForResponse(
    (response) =>
      response
        .url()
        .endsWith("/workloads/workload-dev/configuration-proposals") &&
      response.request().method() === "POST",
  );
  await proposalDialog
    .getByRole("button", { name: "Record blocked proposal", exact: true })
    .click();
  const proposalResponse = await proposed;
  expect(proposalResponse.status()).toBe(201);
  const proposal =
    (await proposalResponse.json()) as components["schemas"]["ConfigurationProposal"];
  expect(proposal.authority_id).toBe(authority.id);
  expect(proposal.authority_hash).toBe(authority.hash);
  expect(proposal.capacity_assessment_id).toBe(capacity.id);
  expect(proposal.capacity_assessment_hash).toBe(capacity.hash);
  expect(proposal.population_hash).toBe(capacity.population_hash);
  expect(proposal.status).toBe("BLOCKED");
  expect(proposal.execution_authorized).toBe(false);
  expect(proposal.estimated_saving).toBeNull();
  expect(proposal.verified_saving).toBeNull();
  expect(proposal.change_plan_id).toBeNull();
  await expect(proposalDialog).not.toBeVisible();
  const proposalRow = authorityPanel
    .getByRole("row")
    .filter({ hasText: proposal.id });
  await expect(proposalRow).toContainText("Execution disabled");
  await expect(proposalRow).toContainText("Estimated savings: unavailable");
  expect(errors).toEqual([]);
});
