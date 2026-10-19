import { expect, test, type Locator, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  FleetHistoryRegistration,
  FleetDemandDefinition,
  FleetHistoryScope,
} from "../src/types";

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
    "The actual journey must run only against the labelled local fixture stack.",
  ).toBe(true);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  return { dashboard, authorization };
}

// Follow actual scoped cursor responses, including when retained prior test
// registrations put a newly created UUID beyond the first page.
async function chooseGroup(
  page: Page,
  group: Locator,
  side: "Original" | "Candidate",
  fleet: string,
) {
  await expect(
    group.getByRole("region", {
      name: `${side} group identity choices`,
      exact: true,
    }),
  ).toBeVisible();
  const target = group.getByRole("button", {
    name: `Use ${side.toLowerCase()} group ${fleet}`,
    exact: true,
  });
  for (;;) {
    if (await target.isVisible()) {
      await target.click();
      return;
    }
    const more = group.getByRole("button", {
      name: `Load more ${side.toLowerCase()} group choices`,
      exact: true,
    });
    await expect(
      more,
      `The registered ${side.toLowerCase()} group must be reachable through authorized cursor pages.`,
    ).toBeVisible();
    const [response] = await Promise.all([
      page.waitForResponse((reply) => {
        const u = new URL(reply.url());
        return (
          u.pathname === "/v1/fleet-history-registrations" &&
          u.searchParams.has("cursor") &&
          reply.ok()
        );
      }),
      more.click(),
    ]);
    const next = (await response.json()) as {
      items: FleetHistoryRegistration[];
    };
    expect(next.items.length).toBeGreaterThan(0);
    await expect(
      group.getByRole("button", {
        name: `Use ${side.toLowerCase()} group ${next.items.at(-1)!.registration.fleet_id}`,
        exact: true,
      }),
    ).toBeVisible();
  }
}

test("real OIDC two registered groups produce a persisted isolated fixture selection while unknown-program approval and runtime remain refused", async ({
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
    "Reuse the independent registered collector; the browser supplies no source receipts.",
  ).toBeTruthy();
  const source = dashboard.source_connections?.find(
    (row) =>
      (process.env.FINOPS_E2E_FLEET_SOURCE_ID
        ? row.id === process.env.FINOPS_E2E_FLEET_SOURCE_ID
        : true) &&
      row.enabled === true &&
      row.revoked !== true &&
      row.kind === "AWS_CUR2" &&
      row.region === "eu-west-1" &&
      (row.payer_account_id === activity!.account_id ||
        row.usage_account_ids.includes(String(activity!.account_id))),
  );
  expect(
    source,
    "An authorized fixture ingestion source with genuine current HEALTHY synchronization is a prerequisite; no browser checkpoint or health upload is permitted.",
  ).toBeTruthy();
  expect(
    source!.status,
    "An enabled registration is not current HEALTHY source evidence; an operator must refresh the approved fixture ingestion before this journey.",
  ).toBe("HEALTHY");
  const profileResponse = await page.request.get("/v1/fleet-fixture-profiles", {
    headers: { Authorization: authorization },
  });
  expect(profileResponse.status()).toBe(200);
  let installations =
    (await profileResponse.json()) as components["schemas"]["FleetFixtureProfilePage"];
  let installed = process.env.FINOPS_E2E_FIXTURE_PROFILE_ID
    ? installations.items.find(
        (row) => row.id === process.env.FINOPS_E2E_FIXTURE_PROFILE_ID,
      )
    : installations.items.at(-1);
  const profileCursors = new Set<string>();
  while (!installed && installations.next_cursor) {
    const cursor = installations.next_cursor;
    expect(
      profileCursors.has(cursor),
      "Profile cursor must advance without replay.",
    ).toBe(false);
    profileCursors.add(cursor);
    const response = await page.request.get(
      `/v1/fleet-fixture-profiles?cursor=${encodeURIComponent(cursor)}`,
      { headers: { Authorization: authorization } },
    );
    expect(response.status()).toBe(200);
    installations =
      (await response.json()) as components["schemas"]["FleetFixtureProfilePage"];
    installed = installations.items.find(
      (row) => row.id === process.env.FINOPS_E2E_FIXTURE_PROFILE_ID,
    );
  }
  expect(
    installed,
    "A real privately commissioned toolchain generation must be installed before this connected journey. The browser cannot install one.",
  ).toBeTruthy();
  const post = async <T>(
    path: string,
    body: unknown,
    version: number,
  ): Promise<T> => {
    const response = await page.request.post(`/v1${path}`, {
      headers: {
        Authorization: authorization,
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": `"${version}"`,
      },
      data: body,
    });
    expect(
      response.status(),
      `Existing public selector setup ${path} must succeed without receipt or authority uploads.`,
    ).toBe(201);
    return (await response.json()) as T;
  };
  const names = [
    `fixture-old-${Date.now()}`,
    `fixture-candidate-${Date.now()}`,
  ];
  const account = String(activity!.account_id),
    pairs: {
      registration: FleetHistoryRegistration;
      proposal: components["schemas"]["FleetConfigurationProposal"];
    }[] = [];
  for (const [index, name] of names.entries()) {
    const registration = await post<FleetHistoryRegistration>(
      "/fleet-history-registrations",
      {
        workload_id: workload!.id,
        fleet_id: name,
        asg_arn: `arn:aws:autoscaling:eu-west-1:${account}:autoScalingGroup:${index === 0 ? "11111111-1111-1111-1111-111111111111" : "22222222-2222-2222-2222-222222222222"}:autoScalingGroupName/${name}`,
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
        business_operation: "Fixture declared completed operations",
        semantic_contract_id: "fixture-completed-v1",
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
    expect(scope.membership_status).toBe("INTERVAL_OWNERSHIP_UNPROVEN");
    const metadata: components["schemas"]["FleetDeclarationInput"] = {
      schema_version: "1",
      authority: "TERRAFORM",
      repository: {
        url: "https://github.com/example/declared-fixture-infrastructure",
        ref: "main",
        directory: "infra",
      },
      pipeline: {
        system: "GITHUB_ACTIONS",
        identity: {
          issuer: "https://token.actions.githubusercontent.com",
          audience: "finops-deployment-observer",
          subject:
            "repo:example/declared-fixture-infrastructure:ref:refs/heads/main",
          pipeline_id: "declared-customer-pipeline",
        },
      },
      terraform: {
        workspace: "development",
        state_lineage: "12345678-1234-1234-1234-123456789abc",
        asg_address: `aws_autoscaling_group.${index === 0 ? "old" : "candidate"}`,
        launch_template_address: `aws_launch_template.${index === 0 ? "old" : "candidate"}`,
        traffic: {
          listener_rule_address: "aws_lb_listener_rule.app",
          target_group_addresses: [
            "aws_lb_target_group.old",
            "aws_lb_target_group.candidate",
          ],
        },
      },
    };
    const base = `/fleet-history-registrations/${registration.id}`;
    const declaration = await post<
      components["schemas"]["FleetConfigurationDeclaration"]
    >(`${base}/configuration-authorities`, metadata, 0);
    const proposal = await post<
      components["schemas"]["FleetConfigurationProposal"]
    >(
      `${base}/configuration-proposals`,
      { declaration_id: declaration.id, scope_id: scope.id },
      declaration.version,
    );
    expect(proposal.status).toBe("BLOCKED");
    expect(proposal.execution_authorized).toBe(false);
    expect(proposal.verified_saving).toBeNull();
    pairs.push({ registration, proposal });
  }
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "Fleet history workload", exact: true })
    .selectOption(workload!.id);
  // The new comparison uses the same actual persisted group selections. No
  // native member receipts are supplied by this browser, so missing evidence
  // must flow through the commissioned daemon as an immutable unavailable result.
  const safetyResponse = await page.request.get(
    `/v1/workloads/${workload!.id}/safety-profiles?limit=1`,
    { headers: { Authorization: authorization } },
  );
  expect(safetyResponse.status()).toBe(200);
  const safety =
    (await safetyResponse.json()) as components["schemas"]["WorkloadSafetyPage"];
  expect(
    safety.latest,
    "The fixture workload must retain its declared safety profile before commissioning the comparison worker.",
  ).toBeTruthy();
  await page
    .getByText("Native fleet assessment & observed compute rates", {
      exact: true,
    })
    .click();
  await page
    .getByRole("button", { name: "Compare fleet compute rates", exact: true })
    .click();
  const assessmentDialog = page.getByRole("dialog", {
    name: "Compare observed fleet compute rates",
    exact: true,
  });
  for (const [index, side] of (["Original", "Candidate"] as const).entries()) {
    const group = assessmentDialog.getByRole("group", {
      name: `${side} group for assessment`,
      exact: true,
    });
    await expect(
      group.getByRole("region", {
        name: `${side} assessment group choices`,
        exact: true,
      }),
    ).toBeVisible();
    const target = group.getByRole("button", {
      name: `Assess ${side.toLowerCase()} group ${names[index]}`,
      exact: true,
    });
    for (;;) {
      if (await target.isVisible()) {
        await target.click();
        break;
      }
      const more = group.getByRole("button", {
        name: `Load more ${side.toLowerCase()} assessment groups`,
        exact: true,
      });
      await expect(more).toBeVisible();
      const [response] = await Promise.all([
        page.waitForResponse((reply) => {
          const u = new URL(reply.url());
          return (
            u.pathname === "/v1/fleet-history-registrations" &&
            u.searchParams.has("cursor") &&
            reply.ok()
          );
        }),
        more.click(),
      ]);
      const next = (await response.json()) as {
        items: FleetHistoryRegistration[];
      };
      expect(next.items.length).toBeGreaterThan(0);
      await expect(
        group.getByRole("button", {
          name: `Assess ${side.toLowerCase()} group ${next.items.at(-1)!.registration.fleet_id}`,
          exact: true,
        }),
      ).toBeVisible();
    }
    await group
      .getByRole("button", {
        name: `Compare ${side.toLowerCase()} proposal ${pairs[index].proposal.id.slice(0, 12)}…${pairs[index].proposal.id.slice(-6)}`,
        exact: true,
      })
      .click();
  }
  const [assessmentResponse] = await Promise.all([
    page.waitForResponse(
      (reply) =>
        new URL(reply.url()).pathname ===
          `/v1/workloads/${workload!.id}/fleet-native-assessments` &&
        reply.request().method() === "POST",
    ),
    assessmentDialog
      .getByRole("button", {
        name: "Request native fleet assessment",
        exact: true,
      })
      .click(),
  ]);
  expect(assessmentResponse.status()).toBe(202);
  expect(assessmentResponse.request().postDataJSON()).toEqual({
    old_configuration_proposal_id: pairs[0].proposal.id,
    candidate_configuration_proposal_id: pairs[1].proposal.id,
  });
  expect(assessmentResponse.request().headers()["if-match"]).toBe(
    `"${safety.latest!.version}"`,
  );
  const requested =
    (await assessmentResponse.json()) as components["schemas"]["FleetNativeAssessmentRecord"];
  expect(requested.status).toBe("QUEUED");
  expect(requested.assessment).toBeNull();
  let assessed: components["schemas"]["FleetNativeAssessmentRecord"] =
    requested;
  await expect
    .poll(
      async () => {
        const response = await page.request.get(
          `/v1/fleet-native-assessments/${requested.id}`,
          { headers: { Authorization: authorization } },
        );
        expect(response.status()).toBe(200);
        assessed =
          (await response.json()) as components["schemas"]["FleetNativeAssessmentRecord"];
        return assessed.status;
      },
      { timeout: 60_000, intervals: [500, 1000, 2000] },
    )
    .toBe("ASSESSED");
  expect(assessed.assessment!.status).toBe("BLOCKED");
  expect(assessed.assessment!.scenario.status).toBe("UNAVAILABLE");
  expect(assessed.assessment!.scenario.hourly_compute_difference).toBeNull();
  expect(assessed.assessment!.verified_saving).toBeNull();
  expect(assessed.execution_authorized).toBe(false);
  await page
    .getByRole("button", { name: "Refresh selected assessment", exact: true })
    .click();
  const assessmentPanel = page.getByRole("region", {
    name: "Selected native fleet assessment",
    exact: true,
  });
  await expect(
    assessmentPanel.getByRole("row", {
      name: "Conditional hourly compute difference Unavailable",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    assessmentPanel.getByRole("row", {
      name: "Verified savings Unavailable",
      exact: true,
    }),
  ).toBeVisible();
  // Reauthentication after a real navigation proves the result is server state.
  // Clear the IdP cookie so this second credential flow cannot silently use SSO.
  await page.context().clearCookies();
  await page.reload();
  await signIn(page, process.env.FINOPS_E2E_USER || "owner");
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "Fleet history workload", exact: true })
    .selectOption(workload!.id);
  await page
    .getByText("Native fleet assessment & observed compute rates", {
      exact: true,
    })
    .click();
  await page
    .getByRole("button", {
      name: `Inspect native assessment ${requested.id.slice(0, 12)}…${requested.id.slice(-6)}`,
      exact: true,
    })
    .click();
  await expect(
    page
      .getByRole("region", {
        name: "Selected native fleet assessment",
        exact: true,
      })
      .getByRole("row", { name: "Verified savings Unavailable", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", {
      name: "Propose isolated group fixture",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Propose an isolated group fixture",
    exact: true,
  });
  const generation = dialog.getByRole("combobox", {
    name: "Installed fixture generation",
    exact: true,
  });
  await expect(generation).toBeVisible();
  while (
    (await generation.locator(`option[value="${installed!.id}"]`).count()) === 0
  ) {
    const more = dialog.getByRole("button", {
      name: "Load more installed fixture generations",
      exact: true,
    });
    await expect(
      more,
      "The privately installed generation must be reachable through cursor pages.",
    ).toBeVisible();
    const [response] = await Promise.all([
      page.waitForResponse((reply) => {
        const u = new URL(reply.url());
        return (
          u.pathname === "/v1/fleet-fixture-profiles" &&
          u.searchParams.has("cursor") &&
          reply.ok()
        );
      }),
      more.click(),
    ]);
    const next =
      (await response.json()) as components["schemas"]["FleetFixtureProfilePage"];
    expect(next.items.length).toBeGreaterThan(0);
    await expect(
      generation.locator(`option[value="${next.items.at(-1)!.id}"]`),
    ).toHaveCount(1);
  }
  await generation.selectOption(installed!.id);
  for (const [index, side] of (["Original", "Candidate"] as const).entries()) {
    const group = dialog.getByRole("group", {
      name: `${side} registered group`,
      exact: true,
    });
    await chooseGroup(page, group, side, names[index]);
    await group
      .getByRole("button", {
        name: `Select ${side.toLowerCase()} proposal ${pairs[index].proposal.id.slice(0, 12)}…${pairs[index].proposal.id.slice(-6)}`,
        exact: true,
      })
      .click();
  }
  const [selectedResponse] = await Promise.all([
    page.waitForResponse(
      (reply) =>
        new URL(reply.url()).pathname === "/v1/fleet-fixture-proposals" &&
        reply.request().method() === "POST",
    ),
    dialog
      .getByRole("button", {
        name: "Record isolated fixture proposal",
        exact: true,
      })
      .click(),
  ]);
  expect(selectedResponse.status()).toBe(201);
  const selected =
    (await selectedResponse.json()) as components["schemas"]["FleetFixtureProposalRecord"];
  expect(selectedResponse.request().postDataJSON()).toEqual({
    old_configuration_proposal_id: pairs[0].proposal.id,
    candidate_configuration_proposal_id: pairs[1].proposal.id,
    fixture_profile_id: installed!.id,
  });
  expect(selectedResponse.request().headers()["if-match"]).toBe('"0"');
  expect(selected.status).toBe("WAITING_FOR_PROGRAM");
  expect(selected.prepared_program).toBeNull();
  expect(selected.approval).toBeNull();
  expect(selected.proposal.binding.old.registration.id).toBe(
    pairs[0].registration.id,
  );
  expect(selected.proposal.binding.candidate.registration.id).toBe(
    pairs[1].registration.id,
  );
  expect(selected.proposal.customer_execution_authorized).toBe(false);
  expect(selected.readiness.verified_saving).toBeNull();
  const details = page.getByRole("dialog", {
    name: "Isolated group fixture proposal",
    exact: true,
  });
  await expect(
    details.getByText("Waiting for private program preparation", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    details.getByRole("button", {
      name: "Approve exact fixture program",
      exact: true,
    }),
  ).toHaveCount(0);
  const persisted = await page.request.get(
    `/v1/fleet-fixture-proposals/${selected.id}`,
    { headers: { Authorization: authorization } },
  );
  expect(persisted.status()).toBe(200);
  expect((await persisted.json()).hash).toBe(selected.hash);
  const preparedMissing = await page.request.get(
    `/v1/fleet-fixture-proposals/${selected.id}/prepared-program`,
    { headers: { Authorization: authorization } },
  );
  expect(preparedMissing.status()).toBe(404);
  const draftPage = await page.request.get(
    `/v1/fleet-fixture-proposals/${selected.id}/authorization-drafts?limit=1`,
    { headers: { Authorization: authorization } },
  );
  expect(draftPage.status()).toBe(200);
  const noDrafts =
    (await draftPage.json()) as components["schemas"]["FleetGroupAuthorityReviewPage"];
  expect(noDrafts.items).toEqual([]);
  expect(noDrafts.next_cursor).toBeNull();
  const inspectRuns = async () => {
    const response = await page.request.get(
      `/v1/fleet-fixture-proposals/${selected.id}/runs?limit=1`,
      { headers: { Authorization: authorization } },
    );
    expect(response.status()).toBe(200);
    const result =
      (await response.json()) as components["schemas"]["FleetFixtureRunPage"];
    expect(result.items).toEqual([]);
    expect(result.next_cursor).toBeNull();
    expect(result.status).toBe("UNAVAILABLE");
    expect(result.reason_codes).toContain(
      "FLEET_FIXTURE_RUNTIME_NOT_CONNECTED",
    );
  };
  await inspectRuns();
  const selfApproval = await page.request.post(
    `/v1/fleet-fixture-proposals/${selected.id}/approvals`,
    {
      headers: {
        Authorization: authorization,
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": `"${selected.version}"`,
      },
      data: {},
    },
  );
  expect(selfApproval.status()).toBe(403);
  expect((await selfApproval.json()).error).toBe(
    "FLEET_FIXTURE_INDEPENDENT_APPROVER_REQUIRED",
  );
  const approveContext = await browser.newContext();
  try {
    const approver = await signIn(
      await approveContext.newPage(),
      process.env.FINOPS_E2E_APPROVER || "approver",
    );
    const response = await approveContext.request.post(
      `/v1/fleet-fixture-proposals/${selected.id}/approvals`,
      {
        headers: {
          Authorization: approver.authorization,
          "Idempotency-Key": crypto.randomUUID(),
          "If-Match": `"${selected.version}"`,
        },
        data: {},
      },
    );
    expect(response.status()).toBe(409);
    expect((await response.json()).error).toBe("PROGRAM_NOT_PREPARED");
  } finally {
    await approveContext.close();
  }
  for (const username of ["viewer", "other"]) {
    const context = await browser.newContext();
    try {
      const actor = await signIn(await context.newPage(), username);
      const expectedRead = username === "other" ? 404 : 200;
      for (const suffix of [
        "",
        "/authorization-drafts?limit=1",
        "/runs?limit=1",
      ]) {
        const response = await context.request.get(
          `/v1/fleet-fixture-proposals/${selected.id}${suffix}`,
          { headers: { Authorization: actor.authorization } },
        );
        expect(response.status()).toBe(expectedRead);
      }
      const denied = await context.request.post(
        `/v1/fleet-fixture-proposals/${selected.id}/approvals`,
        {
          headers: {
            Authorization: actor.authorization,
            "Idempotency-Key": crypto.randomUUID(),
            "If-Match": `"${selected.version}"`,
          },
          data: {},
        },
      );
      expect(denied.status()).toBe(username === "other" ? 404 : 403);
    } finally {
      await context.close();
    }
  }
  const run = await page.request.post(
    `/v1/fleet-fixture-proposals/${selected.id}/runs`,
    {
      headers: {
        Authorization: authorization,
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": `"${selected.version}"`,
      },
      data: {},
    },
  );
  expect(run.status()).toBe(503);
  expect((await run.json()).error).toBe("FLEET_FIXTURE_RUNTIME_NOT_CONNECTED");
  await inspectRuns();
  const unchanged = await page.request.get(
    `/v1/fleet-fixture-proposals/${selected.id}`,
    { headers: { Authorization: authorization } },
  );
  expect(unchanged.status()).toBe(200);
  const final =
    (await unchanged.json()) as components["schemas"]["FleetFixtureProposalRecord"];
  expect(final.version).toBe(selected.version);
  expect(final.hash).toBe(selected.hash);
  expect(final.approval).toBeNull();
  expect(final.prepared_program).toBeNull();
  expect(final.proposal.customer_execution_authorized).toBe(false);
  expect(final.readiness.estimated_saving).toBeNull();
  expect(final.readiness.verified_saving).toBeNull();
  expect(errors).toEqual([]);
});
