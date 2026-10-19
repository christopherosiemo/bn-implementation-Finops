import { createHash } from "node:crypto";
import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type {
  FleetGroupAuthorizationView,
  JournalAuthorizationBody,
  ContinuationAuthorizationBody,
} from "../src/FleetGroupAuthorization";

// Every API/OIDC request below is intercepted. These are presentation fixtures,
// not independent human approval, native execution or PostgreSQL acceptance.
const hash = "a".repeat(64),
  created = "2026-10-19T12:00:00Z",
  expiry = "2026-10-19T20:00:00Z";
const journal: JournalAuthorizationBody = {
  schema_version: "1",
  kind: "ISOLATED_GROUP_TRANSITION_JOURNAL",
  id: "journal-body",
  journal_id: "journal-one",
  parent_envelope_sha256: hash,
  parent_sha256: hash,
  binding_sha256: hash,
  realm_sha256: hash,
  pipeline_id: "fixture-pipeline",
  ref: "refs/heads/approved",
  policy: "STRICT_LIFO_OWNED_INVERSE",
  base: {
    revision: {
      commit: "b".repeat(40),
      tree: "c".repeat(40),
      configuration_sha256: hash,
      desired_sha256: hash,
    },
    state_lineage: "native-fixture-lineage",
    state_serial: 1,
    state_sha256: hash,
    model: {
      binding_sha256: hash,
      realm_sha256: hash,
      old_count: 20,
      candidate_count: 0,
      candidate_traffic_percent: 0,
    },
  },
  pipeline_key_sha256: "d".repeat(64),
  ledger_key_sha256: "e".repeat(64),
  maximum_effects: 32,
  maximum_records: 512,
  created_at: created,
  expires_at: expiry,
  nonce: "journal-nonce",
};
const continuation: ContinuationAuthorizationBody = {
  schema_version: "1",
  id: "continuation-body",
  chain_id: "chain-one",
  policy: "OWNED_RECOVERY_ONLY_SEGMENTS_30M_DRAFT_REVIEW",
  parent_envelope_sha256: hash,
  journal_authorization_sha256: hash,
  binding_sha256: hash,
  realm_sha256: hash,
  signer_key_sha256: "f".repeat(64),
  pipeline_key_sha256: "d".repeat(64),
  ledger_key_sha256: "e".repeat(64),
  bootstrap_head: {
    head: {
      journal_id: "journal-one",
      authorization_sha256: hash,
      ref: { version: 0, record_count: 0, last_record_sha256: "0".repeat(64) },
      projection_sha256: hash,
      observed_at: created,
      valid_until: expiry,
    },
    algorithm: "Ed25519-FleetGroupJournal-v1-current-head",
    signature: "fixture-signature-not-authority",
  },
  record_limit: 512,
  byte_limit: 262144,
  created_at: created,
  forward_expires_at: expiry,
  nonce: "continuation-nonce",
};
function draft(kind: "JOURNAL" | "CONTINUATION"): FleetGroupAuthorizationView {
  const body = kind === "JOURNAL" ? journal : continuation,
    raw = JSON.stringify(body);
  return {
    id: kind === "JOURNAL" ? "journal-draft" : "continuation-draft",
    kind,
    authorization: structuredClone(body),
    authorization_canonical_json: raw,
    authorization_sha256: createHash("sha256").update(raw).digest("hex"),
    created_at: created,
    chain_id: "chain-one",
    prepared_program_id: "prepared-program",
    proposal_id: "proposal-one",
    workload_id: "workload-one",
    creator_id: "creator",
    version: 1,
    status: "AWAITING_APPROVAL",
    approval: null,
    customer_execution_authorized: false,
  } as FleetGroupAuthorizationView;
}

async function open(
  page: Page,
  options: {
    rows?: FleetGroupAuthorizationView[];
    failure?: number;
    badHash?: boolean;
    unavailable?: boolean;
  } = {},
) {
  const rows = structuredClone(
    options.rows ?? [draft("JOURNAL"), draft("CONTINUATION")],
  );
  const writes: {
      path: string;
      body: unknown;
      version?: string;
      idempotency?: string;
    }[] = [],
    queries: string[] = [];
  await page.addInitScript(() => {
    sessionStorage.setItem("finops.oidc.state", "presentation-state");
    sessionStorage.setItem(
      "finops.oidc.verifier",
      "presentation-pending-verifier",
    );
  });
  await page.route("**/.well-known/openid-configuration", (route) =>
    route.fulfill({
      json: {
        authorization_endpoint: "http://127.0.0.1/unused-presentation",
        token_endpoint: `${new URL(page.url()).origin}/__authorization-token`,
      },
    }),
  );
  await page.route("**/__authorization-token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const reply = (json: unknown, status = 200) =>
      route.fulfill({ json, status });
    queries.push(path + url.search);
    if (
      path === "/v1/fleet-fixture-proposals/proposal-one/authorization-drafts"
    ) {
      if (options.unavailable)
        return reply(
          {
            error: "SOURCE_AUTHORITY_UNAVAILABLE",
            message: "Authorization drafts could not be read.",
          },
          503,
        );
      return reply({
        items: url.searchParams.has("cursor")
          ? rows.slice(1)
          : rows.slice(0, 1),
        next_cursor:
          !url.searchParams.has("cursor") && rows.length > 1
            ? "opaque-next-authorization"
            : null,
      });
    }
    const row = rows.find((item) =>
      path.startsWith(`/v1/fleet-group-authorizations/${item.id}`),
    );
    if (!row)
      return reply(
        { error: "NOT_FOUND", message: "No presentation fixture." },
        404,
      );
    if (request.method() === "POST") {
      writes.push({
        path,
        body: request.postDataJSON(),
        version: request.headers()["if-match"],
        idempotency: request.headers()["idempotency-key"],
      });
      if (options.failure)
        return reply(
          {
            error:
              options.failure === 403
                ? "INDEPENDENT_APPROVER_REQUIRED"
                : "VERSION_CONFLICT",
            message:
              options.failure === 403
                ? "The creator cannot approve this authorization."
                : "The authorization revision changed.",
          },
          options.failure,
        );
      row.version++;
      row.status = "APPROVED";
      row.approval = {
        id: "approval-one",
        actor_id: "independent-approver",
        role: "fleet_approver",
        authorization_sha256: row.authorization_sha256,
        approved_at: created,
      };
      return reply(row, 201);
    }
    return reply(
      options.badHash ? { ...row, authorization_sha256: "0".repeat(64) } : row,
    );
  });
  await page.goto(
    "/tests/fixtures/fleet-group-authorization.html?code=presentation&state=presentation-state&proposal=proposal-one",
  );
  await expect(
    page.getByRole("heading", {
      name: "Exact journal & continuation authorizations",
      exact: true,
    }),
  ).toBeVisible();
  return { writes, queries };
}

test("exact journal review verifies canonical bytes and posts only empty approval with current CAS and idempotency", async ({
  page,
}) => {
  const { writes } = await open(page);
  await page
    .getByRole("button", {
      name: "Review journal authorization journal-draft",
      exact: true,
    })
    .click();
  const review = page.getByRole("region", {
    name: "Exact authorization draft review",
    exact: true,
  });
  await expect(
    review.getByText("Exact authorization SHA-256 verified.", { exact: true }),
  ).toBeVisible();
  await expect(
    review.getByLabel("Complete exact authorization JSON", { exact: true }),
  ).toContainText('"maximum_records": 512');
  await expect(review).toContainText(journal.pipeline_key_sha256);
  await expect(review).toContainText(journal.ledger_key_sha256);
  const approve = review.getByRole("button", {
    name: "Approve exact journal authorization",
    exact: true,
  });
  await expect(approve).toBeDisabled();
  await review.getByRole("checkbox").check();
  await approve.click();
  await expect(
    page.getByText("Persisted independent approval", { exact: true }),
  ).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    path: "/v1/fleet-group-authorizations/journal-draft/approvals",
    body: {},
    version: '"1"',
  });
  expect(writes[0].idempotency!.length).toBeGreaterThan(7);
  await expect(page.locator('input[type="file"]')).toHaveCount(0);
});

test("continuation cursor review exposes complete bootstrap proof, signer pin and forward deadline separately from owned recovery", async ({
  page,
}) => {
  const { writes, queries } = await open(page);
  await page
    .getByRole("button", {
      name: "Load more authorization drafts",
      exact: true,
    })
    .click();
  await page
    .getByRole("button", {
      name: "Review continuation authorization continuation-draft",
      exact: true,
    })
    .click();
  const review = page.getByRole("region", {
    name: "Exact authorization draft review",
    exact: true,
  });
  await expect(
    review.getByText("Exact authorization SHA-256 verified.", { exact: true }),
  ).toBeVisible();
  await expect(review).toContainText("Signer key pin");
  await expect(review).toContainText("Forward deadline");
  await expect(review).toContainText(
    "Owned recovery still requires its own fresh, current authority.",
  );
  await expect(
    review.getByLabel("Complete exact authorization JSON", { exact: true }),
  ).toContainText('"bootstrap_head"');
  expect(queries).toContain(
    "/v1/fleet-fixture-proposals/proposal-one/authorization-drafts?limit=10&cursor=opaque-next-authorization",
  );
  expect(writes).toEqual([]);
});

test("tampered exact hash prevents approval and preserves complete uint64 literals without invented rounded serials", async ({
  page,
}) => {
  const row = draft("JOURNAL");
  row.authorization_canonical_json = row.authorization_canonical_json.replace(
    '"state_serial":1',
    '"state_serial":18446744073709551615',
  );
  row.authorization = JSON.parse(
    row.authorization_canonical_json,
  ) as JournalAuthorizationBody;
  row.authorization_sha256 = createHash("sha256")
    .update(row.authorization_canonical_json)
    .digest("hex");
  await open(page, { rows: [row], badHash: true });
  await page
    .getByRole("button", {
      name: "Review journal authorization journal-draft",
      exact: true,
    })
    .click();
  const review = page.getByRole("region", {
    name: "Exact authorization draft review",
    exact: true,
  });
  await expect(review.getByRole("alert")).toContainText(
    "does not match its stored SHA-256",
  );
  await expect(
    review.getByLabel("Complete exact authorization JSON", { exact: true }),
  ).toContainText("18446744073709551615");
  await expect(review).toContainText("outside browser integer range");
  await expect(review.getByRole("checkbox")).toBeDisabled();
  await expect(
    review.getByRole("button", {
      name: "Approve exact journal authorization",
      exact: true,
    }),
  ).toBeDisabled();
});

for (const status of [403, 409])
  test(`server ${status} denial never becomes a local approval or an execution control`, async ({
    page,
  }) => {
    const { writes } = await open(page, {
      rows: [draft("JOURNAL")],
      failure: status,
    });
    await page
      .getByRole("button", {
        name: "Review journal authorization journal-draft",
        exact: true,
      })
      .click();
    const review = page.getByRole("region", {
      name: "Exact authorization draft review",
      exact: true,
    });
    await expect(
      review.getByText("Exact authorization SHA-256 verified.", {
        exact: true,
      }),
    ).toBeVisible();
    await review.getByRole("checkbox").check();
    await review
      .getByRole("button", {
        name: "Approve exact journal authorization",
        exact: true,
      })
      .click();
    await expect(review.getByRole("alert")).toContainText(
      status === 403 ? "creator cannot approve" : "revision changed",
    );
    await expect(
      page.getByText("Persisted independent approval", { exact: true }),
    ).toHaveCount(0);
    expect(writes).toHaveLength(1);
    await expect(
      page.getByRole("button", { name: /execute|start run/i }),
    ).toHaveCount(0);
  });

test("missing drafts remain empty and never invent approval", async ({
  page,
}) => {
  const { writes } = await open(page, { rows: [] });
  await expect(
    page.getByText("No authorization drafts", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /^Approve exact/ }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);
});

test("service failure is distinct from empty authorization drafts", async ({
  page,
}) => {
  const { writes } = await open(page, { unavailable: true });
  await expect(page.getByRole("alert")).toContainText(
    "Authorization drafts could not be read.",
  );
  await expect(
    page.getByText("No authorization drafts", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /^Approve exact/ }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);
});
