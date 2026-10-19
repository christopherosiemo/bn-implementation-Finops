import { expect, test, type Browser, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  FleetDemandDefinition,
  FleetHistoryRegistration,
  FleetHistoryScope,
} from "../src/types";

type Declaration = components["schemas"]["FleetConfigurationDeclaration"];
type Proposal = components["schemas"]["FleetConfigurationProposal"];
async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page
    .getByRole("button", { name: "Sign in to your workspace", exact: true })
    .click();
  await page.getByRole("textbox", { name: /username/i }).fill(username);
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  const [response] = await Promise.all([
    page.waitForResponse(
      (reply) => reply.url().endsWith("/v1/dashboard") && reply.ok(),
    ),
    page.getByRole("button", { name: "Sign In", exact: true }).click(),
  ]);
  const dashboard = (await response.json()) as Dashboard;
  expect(
    dashboard.fixture,
    "This journey may mutate only the explicitly labelled local fixture stack.",
  ).toBe(true);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  return { dashboard, authorization };
}
async function secondary(browser: Browser, username: string) {
  const context = await browser.newContext(),
    page = await context.newPage();
  return { context, page, ...(await signIn(page, username)) };
}

test("real OIDC registered fleet metadata and ID-selected history produce a persisted blocked proposal without singleton or execution authority", async ({
  page,
  browser,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const { dashboard, authorization } = await signIn(
    page,
    process.env.FINOPS_E2E_USER || "owner",
  );
  const workload = dashboard.workloads.find((row) => row.id === "workload-dev");
  expect(workload).toBeTruthy();
  const activity = dashboard.activity_sources?.find(
    (row) =>
      row.enabled === true &&
      row.workload_id === workload!.id &&
      row.region === "eu-west-1",
  );
  expect(
    activity,
    "The genuine independent collector registration is a prerequisite; the browser uploads no source receipts.",
  ).toBeTruthy();
  const account = String(activity!.account_id);
  let source = dashboard.source_connections?.find(
    (row) =>
      row.enabled === true &&
      row.kind === "AWS_CUR2" &&
      row.region === "eu-west-1" &&
      (row.payer_account_id === account ||
        row.usage_account_ids.includes(account)),
  );
  const post = async <T>(
    path: string,
    body: unknown,
    version?: number,
  ): Promise<T> => {
    const response = await page.request.post(`/v1${path}`, {
      headers: {
        Authorization: authorization,
        "Idempotency-Key": crypto.randomUUID(),
        ...(version === undefined ? {} : { "If-Match": `"${version}"` }),
      },
      data: body,
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as T;
  };
  if (!source) {
    expect(account).toBe("111122223333");
    // Public deterministic fixture registration coordinates only. No sync,
    // native observations, archived artifacts or historical data are uploaded.
    const sourceRequest: components["schemas"]["SourceConnectionRequest"] = {
      kind: "AWS_CUR2",
      payer_account_id: account,
      usage_account_ids: [account],
      region: "eu-west-1",
      export_arn: `arn:aws:bcm-data-exports:us-east-1:${account}:export/fixture-export`,
      read_role_binding_id: "fixture-payer",
      bucket: "finops-fixture-cur2",
      bucket_owner: account,
      prefix: "cur/",
    };
    source = await post<NonNullable<Dashboard["source_connections"]>[number]>(
      "/source-connections",
      sourceRequest,
    );
  }
  const fleet = `browser-fleet-config-${Date.now()}`;
  const registration = await post<FleetHistoryRegistration>(
    "/fleet-history-registrations",
    {
      workload_id: workload!.id,
      fleet_id: fleet,
      asg_arn: `arn:aws:autoscaling:eu-west-1:${account}:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/${fleet}`,
      source_connection_id: source!.id,
      cadence_seconds: 60,
      max_gap_seconds: 120,
    },
    0,
  );
  const definition = await post<FleetDemandDefinition>(
    "/fleet-demand-definitions",
    {
      registration_id: registration.id,
      activity_source_id: activity!.id,
      business_operation: "Fixture completed operations — declared semantics",
      semantic_contract_id: `fixture-fleet-config-${fleet}`,
      semantic_contract_hash: "c".repeat(64),
    },
    0,
  );
  const scope = await post<FleetHistoryScope>(
    "/fleet-history-scopes",
    {
      registration_id: registration.id,
      definition_id: definition.id,
      definition_version: definition.version,
    },
    registration.version,
  );
  expect(scope.status).toBe("BLOCKED");
  expect(scope.membership_status).toBe("INTERVAL_OWNERSHIP_UNPROVEN");
  expect(scope.demand.window_units).toBeNull();
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "Fleet history workload", exact: true })
    .selectOption(workload!.id);
  const inspect = page.getByRole("button", {
    name: `Inspect fleet history ${fleet}`,
    exact: true,
  });
  const more = page.getByRole("button", {
    name: "Load more fleet history registrations",
    exact: true,
  });
  for (let count = 0; !(await inspect.count()) && count < 20; count++) {
    await expect(more).toBeVisible();
    await more.click();
  }
  await inspect.click();
  const dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  await dialog
    .getByText("Fleet configuration declarations & blocked proposals", {
      exact: true,
    })
    .click();
  await dialog
    .getByRole("button", {
      name: "Declare fleet Terraform metadata",
      exact: true,
    })
    .click();
  const metadata: components["schemas"]["FleetDeclarationInput"] = {
    schema_version: "1",
    authority: "TERRAFORM",
    repository: {
      url: "https://github.com/example/finops-fixture-infrastructure",
      ref: "main",
      directory: "infra/api",
    },
    pipeline: {
      system: "GITHUB_ACTIONS",
      identity: {
        issuer: "https://token.actions.githubusercontent.com",
        audience: "finops-deployment-observer",
        subject:
          "repo:example/finops-fixture-infrastructure:ref:refs/heads/main",
        pipeline_id: "fixture-fleet-deployment-declaration",
      },
    },
    terraform: {
      workspace: "development",
      state_lineage: "12345678-1234-1234-1234-123456789abc",
      asg_address: "module.api.aws_autoscaling_group.api",
      launch_template_address: "module.api.aws_launch_template.api",
    },
  };
  const values = {
    "Fleet repository HTTPS URL": metadata.repository.url,
    "Fleet declared Git branch or tag": metadata.repository.ref,
    "Fleet repository relative directory": metadata.repository.directory,
    "Fleet pipeline issuer HTTPS URL": metadata.pipeline.identity.issuer,
    "Fleet exact pipeline machine subject": metadata.pipeline.identity.subject,
    "Fleet stable pipeline identifier": metadata.pipeline.identity.pipeline_id,
    "Fleet Terraform workspace": metadata.terraform.workspace,
    "Fleet declared state lineage UUID": metadata.terraform.state_lineage,
    "Fleet ASG Terraform resource address": metadata.terraform.asg_address,
    "Fleet launch-template Terraform resource address":
      metadata.terraform.launch_template_address,
  };
  for (const [label, value] of Object.entries(values))
    await dialog.getByLabel(label, { exact: true }).fill(value);
  await dialog
    .getByLabel("I acknowledge that this declaration is unattested", {
      exact: false,
    })
    .check();
  const authorityPath = `/v1/fleet-history-registrations/${registration.id}/configuration-authorities`;
  const savedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(authorityPath) &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save fleet declaration", exact: true })
    .click();
  const saved = await savedResponse;
  expect(saved.status()).toBe(201);
  expect(saved.request().headers()["if-match"]).toBe('"0"');
  expect(saved.request().postDataJSON()).toEqual(metadata);
  const first = (await saved.json()) as Declaration;
  expect(first.status).toBe("DECLARED_NOT_ATTESTED");
  expect(first.execution_authorized).toBe(false);
  expect(first.estimated_saving).toBeNull();
  expect(first.verified_saving).toBeNull();
  expect(first.binding).not.toHaveProperty("resource_id");
  expect(first.registration_hash).toBe(registration.hash);
  await expect(dialog).toContainText(
    "Unavailable · independent attestation required",
  );
  await dialog
    .getByRole("button", { name: "Revise fleet declaration", exact: true })
    .click();
  await dialog
    .getByLabel("Fleet declared Git branch or tag", { exact: true })
    .fill("fixture-review");
  await dialog
    .getByLabel("I acknowledge that this declaration is unattested", {
      exact: false,
    })
    .check();
  const revisedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(authorityPath) &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save fleet declaration", exact: true })
    .click();
  const revised = await revisedResponse;
  expect(revised.status()).toBe(201);
  expect(revised.request().headers()["if-match"]).toBe('"1"');
  const latest = (await revised.json()) as Declaration;
  expect(latest.version).toBe(2);
  expect(latest.id).not.toBe(first.id);
  await dialog
    .getByRole("button", {
      name: "Review fleet proposal evidence",
      exact: true,
    })
    .click();
  await dialog
    .getByLabel(`Select fleet proposal scope ${scope.id}`, { exact: true })
    .check();
  const proposalPath = `/v1/fleet-history-registrations/${registration.id}/configuration-proposals`;
  const proposedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(proposalPath) &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Record blocked fleet proposal", exact: true })
    .click();
  const proposed = await proposedResponse;
  expect(proposed.status()).toBe(201);
  expect(proposed.request().headers()["if-match"]).toBe('"2"');
  expect(proposed.request().postDataJSON()).toEqual({
    declaration_id: latest.id,
    scope_id: scope.id,
  });
  const proposal = (await proposed.json()) as Proposal;
  expect(proposal.status).toBe("BLOCKED");
  expect(proposal.execution_authorized).toBe(false);
  expect(proposal.change_plan_id).toBeNull();
  expect(proposal.estimated_saving).toBeNull();
  expect(proposal.verified_saving).toBeNull();
  expect(proposal.scope_reference_root).toBe(scope.reference_root);
  expect(proposal.reason_codes).toContain("FLEET_CAPACITY_UNPROVEN");
  const evidence = dialog.getByRole("region", {
    name: `Immutable fleet configuration proposal ${proposal.id}`,
    exact: true,
  });
  await expect(evidence).toContainText(
    "No executable plan or savings claim was created",
  );
  await expect(evidence).toContainText(proposal.hash);
  await expect(
    dialog.getByRole("button", { name: /approve|execute|verify savings/i }),
  ).toHaveCount(0);
  const get = async (path: string) => {
    const response = await page.request.get(path, {
      headers: { Authorization: authorization },
    });
    expect(response.status()).toBe(200);
    return response.json();
  };
  expect(await get(`${proposalPath}/${proposal.id}`)).toEqual(proposal);
  const one = (await get(
    `${authorityPath}?limit=1`,
  )) as components["schemas"]["FleetConfigurationPage"];
  expect(one.latest!.id).toBe(latest.id);
  expect(one.items).toHaveLength(1);
  expect(one.next_cursor).toBeTruthy();
  const two = (await get(
    `${authorityPath}?limit=1&cursor=${encodeURIComponent(one.next_cursor!)}`,
  )) as components["schemas"]["FleetConfigurationPage"];
  expect(new Set([...one.items, ...two.items].map((row) => row.id))).toEqual(
    new Set([first.id, latest.id]),
  );
  expect(two.next_cursor).toBeNull();
  await evidence.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: test.info().outputPath("fleet-configuration-desktop.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await evidence.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: test.info().outputPath("fleet-configuration-mobile.png"),
    animations: "disabled",
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  expect(errors).toEqual([]);
  const foreign = await secondary(browser, "other");
  try {
    for (const path of [
      authorityPath,
      proposalPath,
      `${proposalPath}/${proposal.id}`,
    ]) {
      const response = await foreign.page.request.get(path, {
        headers: { Authorization: foreign.authorization },
      });
      expect(response.status()).toBe(404);
      expect(JSON.stringify(await response.json())).not.toContain(
        proposal.hash,
      );
    }
  } finally {
    await foreign.context.close();
  }
  const viewer = await secondary(browser, "viewer");
  try {
    const response = await viewer.page.request.post(authorityPath, {
      headers: {
        Authorization: viewer.authorization,
        "Idempotency-Key": saved.request().headers()["idempotency-key"],
        "If-Match": '"0"',
      },
      data: metadata,
    });
    expect(response.status()).toBe(403);
  } finally {
    await viewer.context.close();
  }
});
