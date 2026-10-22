import { useEffect, useState } from "react";
import { api } from "./api";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Table, dateTime, readable, shortId } from "./ui";

import type { components } from "./api.generated";

export type JournalAuthorizationBody =
  components["schemas"]["FleetGroupJournalAuthorization"];
export type ContinuationAuthorizationBody =
  components["schemas"]["FleetGroupContinuationAuthorization"];
export type FleetGroupAuthorizationView =
  components["schemas"]["FleetGroupAuthorityReview"];
type Props = { proposalId: string; onChanged?: () => void };
const query = encodeURIComponent;
const exactInteger = (value: number) =>
  Number.isSafeInteger(value)
    ? String(value)
    : "See exact body; outside browser integer range";

// Format whitespace without parsing/stringifying numbers, so uint64 state
// serials and counters remain the exact literal received from PostgreSQL.
function formatExactJSON(raw: string): string {
  let out = "",
    depth = 0,
    quoted = false,
    escaped = false;
  const newline = () => {
    out += "\n" + "  ".repeat(Math.max(depth, 0));
  };
  for (const char of raw) {
    if (quoted) {
      out += char;
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
      continue;
    }
    if (char === '"') {
      quoted = true;
      out += char;
    } else if (char === "{" || char === "[") {
      out += char;
      depth++;
      newline();
    } else if (char === "}" || char === "]") {
      depth--;
      newline();
      out += char;
    } else if (char === ",") {
      out += char;
      newline();
    } else if (char === ":") out += ": ";
    else if (!/\s/.test(char)) out += char;
  }
  return out;
}
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, sorted(item)]),
    );
  return value;
}
function useExactBody(draft: FleetGroupAuthorizationView) {
  const key = `${draft.id}:${draft.authorization_sha256}:${draft.authorization_canonical_json}`;
  const [check, setCheck] = useState<{
    key: string;
    valid: boolean;
    error?: string;
  }>({ key, valid: false });
  useEffect(() => {
    let active = true;
    setCheck({ key, valid: false });
    void (async () => {
      try {
        if (
          !/^[a-f0-9]{64}$/.test(draft.authorization_sha256) ||
          typeof draft.authorization_canonical_json !== "string" ||
          draft.authorization_canonical_json.length > 262144
        )
          throw new Error(
            "The exact stored authorization body is unavailable or exceeds the review bound.",
          );
        const decoded: unknown = JSON.parse(draft.authorization_canonical_json);
        if (
          !decoded ||
          typeof decoded !== "object" ||
          Array.isArray(decoded) ||
          JSON.stringify(sorted(decoded)) !==
            JSON.stringify(sorted(draft.authorization))
        )
          throw new Error(
            "The authorization summary differs from its exact stored body. Refresh before reviewing.",
          );
        const digest = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(draft.authorization_canonical_json),
        );
        const observed = [...new Uint8Array(digest)]
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join("");
        if (observed !== draft.authorization_sha256)
          throw new Error(
            "The exact authorization body does not match its stored SHA-256. Approval is unavailable.",
          );
        if (active) setCheck({ key, valid: true });
      } catch (reason) {
        if (active)
          setCheck({
            key,
            valid: false,
            error:
              reason instanceof Error
                ? reason.message
                : "Exact authorization verification failed.",
          });
      }
    })();
    return () => {
      active = false;
    };
  }, [
    key,
    draft.authorization,
    draft.authorization_sha256,
    draft.authorization_canonical_json,
  ]);
  return check.key === key ? check : { key, valid: false };
}

function DraftReview({
  draft,
  onSaved,
}: {
  draft: FleetGroupAuthorizationView;
  onSaved: () => void;
}) {
  const exact = useExactBody(draft),
    [reviewed, setReviewed] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const body = draft.authorization;
  return (
    <section
      className="configuration-stack"
      aria-label="Exact authorization draft review"
    >
      <h4>
        {draft.kind === "JOURNAL"
          ? "Journal authorization"
          : "Recovery continuation authorization"}
      </h4>
      <Badge value={draft.status} />
      <p className="form-note">
        Approval binds this exact persisted authorization body. The prepared
        parent program approval does not substitute for it. Customer execution
        and verified savings remain unavailable; approval alone does not start a
        command.
      </p>
      <dl className="evidence-grid">
        <div>
          <dt>Authorization SHA-256</dt>
          <dd className="evidence-id">{draft.authorization_sha256}</dd>
        </div>
        <div>
          <dt>Prepared program / proposal</dt>
          <dd className="evidence-id">
            {draft.prepared_program_id}
            <small>{draft.proposal_id}</small>
          </dd>
        </div>
        <div>
          <dt>Creator / revision</dt>
          <dd>
            {draft.creator_id}
            <small>
              Revision {draft.version} · created {dateTime(draft.created_at)}
            </small>
          </dd>
        </div>
        <div>
          <dt>Policy</dt>
          <dd>
            {readable(body.policy)}
            <small>
              Parent envelope{" "}
              <span className="evidence-id">{body.parent_envelope_sha256}</span>
            </small>
          </dd>
        </div>
        <div>
          <dt>Binding / fixture realm</dt>
          <dd className="evidence-id">
            {body.binding_sha256}
            <small>{body.realm_sha256}</small>
          </dd>
        </div>
        <div>
          <dt>Pipeline key pin</dt>
          <dd className="evidence-id">{body.pipeline_key_sha256}</dd>
        </div>
        <div>
          <dt>Ledger key pin</dt>
          <dd className="evidence-id">{body.ledger_key_sha256}</dd>
        </div>
        {draft.kind === "JOURNAL" ? (
          <>
            <div>
              <dt>Journal / controlled ref</dt>
              <dd className="evidence-id">
                {draft.authorization.journal_id}
                <small>{draft.authorization.ref}</small>
              </dd>
            </div>
            <div>
              <dt>Effect / record bounds</dt>
              <dd>
                {exactInteger(draft.authorization.maximum_effects)} effects
                <small>
                  {exactInteger(draft.authorization.maximum_records)} records
                </small>
              </dd>
            </div>
            <div>
              <dt>Native base state</dt>
              <dd className="evidence-id">
                {draft.authorization.base.state_lineage}
                <small>
                  Serial {exactInteger(draft.authorization.base.state_serial)}
                </small>
                <small>{draft.authorization.base.state_sha256}</small>
              </dd>
            </div>
            <div>
              <dt>Authorization expiry</dt>
              <dd>{dateTime(draft.authorization.expires_at)}</dd>
            </div>
          </>
        ) : (
          <>
            <div>
              <dt>Chain / original authorization</dt>
              <dd className="evidence-id">
                {draft.authorization.chain_id}
                <small>
                  {draft.authorization.journal_authorization_sha256}
                </small>
              </dd>
            </div>
            <div>
              <dt>Signer key pin</dt>
              <dd className="evidence-id">
                {draft.authorization.signer_key_sha256}
              </dd>
            </div>
            <div>
              <dt>Segment bounds</dt>
              <dd>
                {exactInteger(draft.authorization.record_limit)} records
                <small>
                  {exactInteger(draft.authorization.byte_limit)} bytes
                </small>
              </dd>
            </div>
            <div>
              <dt>Forward deadline</dt>
              <dd>
                {dateTime(draft.authorization.forward_expires_at)}
                <small>
                  Owned recovery still requires its own fresh, current
                  authority.
                </small>
              </dd>
            </div>
          </>
        )}
      </dl>
      <h4>Complete exact authorization body</h4>
      <p className="form-note">
        Whitespace is formatted for reading. SHA-256 is checked against the
        exact stored bytes; integer literals are preserved without rounding.
      </p>
      {exact.error ? (
        <p role="alert" className="blocker-text">
          {exact.error}
        </p>
      ) : !exact.valid ? (
        <p role="status">Verifying exact authorization bytes…</p>
      ) : (
        <p role="status">Exact authorization SHA-256 verified.</p>
      )}
      <pre
        aria-label="Complete exact authorization JSON"
        tabIndex={0}
        style={{
          whiteSpace: "pre-wrap",
          overflowWrap: "anywhere",
          wordBreak: "break-word",
          maxWidth: "100%",
          fontSize: "0.75rem",
          lineHeight: 1.6,
        }}
      >
        {typeof draft.authorization_canonical_json === "string"
          ? formatExactJSON(draft.authorization_canonical_json)
          : "Exact stored body unavailable"}
      </pre>
      {draft.approval ? (
        <div>
          <h4>Persisted independent approval</h4>
          <p>
            {draft.approval.actor_id} · {dateTime(draft.approval.approved_at)}
          </p>
          <p className="evidence-id">{draft.approval.authorization_sha256}</p>
          <p className="form-note">
            Historical approval does not renew expired evidence or grant
            customer authority.
          </p>
        </div>
      ) : (
        <>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={!exact.valid || busy}
              onChange={(event) => setReviewed(event.target.checked)}
            />
            I reviewed this exact authorization, key pins, policy, limits and
            time bounds.
          </label>
          <p className="form-note">
            A current APPROVER must be a different authenticated person from
            creator {draft.creator_id}. The server rechecks role, workload
            access, exact hash and revision.
          </p>
          {error && (
            <p role="alert" className="blocker-text">
              {error}
            </p>
          )}
          <Button
            pending={busy}
            disabled={!reviewed || !exact.valid}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                await api.mutate(
                  `/fleet-group-authorizations/${query(draft.id)}/approvals`,
                  {},
                  draft.version,
                );
                setReviewed(false);
                onSaved();
              } catch (reason) {
                setError(
                  reason instanceof Error
                    ? reason.message
                    : "The authorization was not approved.",
                );
              } finally {
                setBusy(false);
              }
            }}
          >
            Approve exact{" "}
            {draft.kind === "JOURNAL" ? "journal" : "continuation"}{" "}
            authorization
          </Button>
        </>
      )}
    </section>
  );
}

function AuthorizationScope({ proposalId, onChanged }: Props) {
  const [refresh, setRefresh] = useState(0),
    [selected, setSelected] = useState<string | null>(null);
  const detail = useRemote<FleetGroupAuthorizationView>(
    selected ? `/fleet-group-authorizations/${query(selected)}` : null,
    refresh,
  );
  const saved = () => {
    setRefresh((n) => n + 1);
    onChanged?.();
  };
  return (
    <section
      className="configuration-stack"
      aria-label="Independent execution authorization reviews"
    >
      <h3>Exact journal & continuation authorizations</h3>
      <p className="form-note">
        These server-created drafts follow persisted approval of the exact
        parent program. Each authorization requires its own independent
        approval. This view cannot create drafts, upload keys or artifacts, or
        authorize an unknown future body.
      </p>
      <RemotePage<FleetGroupAuthorizationView>
        key={`${proposalId}:${refresh}`}
        path={`/fleet-fixture-proposals/${query(proposalId)}/authorization-drafts?limit=10`}
        label="Authorization drafts"
        empty="No exact authorization has been privately prepared for this approved parent. Missing drafts do not authorize execution."
      >
        {(items) => (
          <Table
            scrollLabel="Persisted exact authorization drafts"
            headings={[
              "Kind / identity",
              "Exact body hash",
              "Approval",
              "Review",
            ]}
          >
            {items.map((row) => (
              <tr key={row.id}>
                <td>
                  {row.kind === "JOURNAL" ? "Journal" : "Recovery continuation"}
                  <small>{shortId(row.id)}</small>
                </td>
                <td className="evidence-id">{row.authorization_sha256}</td>
                <td>
                  <Badge value={row.status} />
                  <small>Revision {row.version}</small>
                </td>
                <td>
                  <Button secondary small onClick={() => setSelected(row.id)}>
                    Review {row.kind.toLowerCase()} authorization{" "}
                    {shortId(row.id)}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {detail.loading && (
        <p role="status">Loading the exact stored authorization…</p>
      )}
      {detail.error && (
        <p role="alert" className="blocker-text">
          Authorization review unavailable. {detail.error}
        </p>
      )}
      {detail.value && (
        <DraftReview
          key={`${detail.value.id}:${detail.value.version}:${detail.value.authorization_sha256}`}
          draft={detail.value}
          onSaved={saved}
        />
      )}
      <Button secondary small onClick={saved}>
        Refresh authorization drafts
      </Button>
    </section>
  );
}

export function FleetGroupAuthorization(props: Props) {
  return <AuthorizationScope key={props.proposalId} {...props} />;
}
