import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Boxes,
  CircleCheck,
  Cloud,
  Command,
  CreditCard,
  ExternalLink,
  FileClock,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  Menu,
  Pause,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Timer,
  X,
} from "lucide-react";
import { api } from "./api";
import { auth } from "./auth";
import { CostAllocation } from "./CostAllocation";
import {
  AuditPage,
  ConnectionsPage,
  ExecutionsPage,
  RecommendationsPage,
  SavingsPage,
  SchedulesPage,
  WorkloadsPage,
} from "./pages";
import {
  Badge,
  Button,
  Empty,
  Metric,
  Panel,
  TextLink,
  currentVerifiedSavings,
  dateTime,
  money,
  preExecutionReady,
  resourceReadiness,
  readable,
  sumMoney,
  type RunMutation,
} from "./ui";
import type { Dashboard, Page } from "./types";

const navigation: { id: Page; label: string; icon: typeof LayoutDashboard }[] =
  [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "workloads", label: "Workloads & resources", icon: Boxes },
    { id: "recommendations", label: "Recommendations", icon: Sparkles },
    { id: "schedules", label: "Schedules & policies", icon: Timer },
    { id: "executions", label: "Executions", icon: Activity },
    { id: "savings", label: "Savings evidence", icon: CreditCard },
    { id: "allocation", label: "Cost allocation", icon: Boxes },
    { id: "connections", label: "Connections & quality", icon: Cloud },
    { id: "audit", label: "Audit trail", icon: FileClock },
  ];
const pageFromHash = (): Page => {
  const id = window.location.hash.slice(1);
  return navigation.some((item) => item.id === id) ? (id as Page) : "overview";
};

function Overview({
  data,
  navigate,
  run,
  busy,
}: {
  data: Dashboard;
  navigate: (page: Page) => void;
  run: RunMutation;
  busy: boolean;
}) {
  const eligible = data.resources.filter((resource) =>
    preExecutionReady(resourceReadiness(data, resource.id)),
  );
  const currency = data.recommendations.find((item) => item.currency)?.currency;
  const newest = new Map(
    data.recommendations.map((item) => [item.resource_id || item.id, item]),
  );
  const candidates = [...newest.values()].filter(
    (item) =>
      item.currency === currency &&
      preExecutionReady(item) &&
      !/BLOCKED|EXPIRED|REJECTED|SUPERSEDED/.test(item.status),
  );
  const monthly = sumMoney(candidates.map((item) => item.monthly_saving));
  const verifiedRecords = currentVerifiedSavings(data.savings);
  const savingCurrency = verifiedRecords[0]?.currency || currency;
  const verified = sumMoney(
    verifiedRecords
      .filter(
        (item) =>
          item.status === "VERIFIED" && item.currency === savingCurrency,
      )
      .map((item) => item.verified_saving),
  );
  const active = data.executions.filter(
    (item) => !/COMPLETED|FAILED|SKIPPED|CANCELLED/.test(item.status),
  );
  const awaiting = data.change_plans.filter(
    (item) => !/APPROVED|EXECUTED|COMPLETED|REJECTED|EXPIRED/.test(item.status),
  );
  const latest = data.executions.at(-1);
  const steps = [
    {
      name: "Discover",
      detail: `${data.resources.length} resources inventoried`,
      done: data.resources.length > 0,
      page: "workloads" as Page,
    },
    {
      name: "Recommend",
      detail: `${data.recommendations.length} evidence-backed findings`,
      done: data.recommendations.length > 0,
      page: "recommendations" as Page,
    },
    {
      name: "Approve",
      detail: `${data.change_plans.filter((item) => /APPROVED|EXECUTED|COMPLETED/.test(item.status)).length} plans approved`,
      done: data.change_plans.some((item) =>
        /APPROVED|EXECUTED|COMPLETED/.test(item.status),
      ),
      page: "schedules" as Page,
    },
    {
      name: "Restore",
      detail: latest
        ? readable(latest.stage || latest.status)
        : "No executions yet",
      done: data.executions.some((item) => item.status === "COMPLETED"),
      page: "executions" as Page,
    },
    {
      name: "Verify",
      detail: `${verifiedRecords.length} verified records`,
      done: verifiedRecords.length > 0,
      page: "savings" as Page,
    },
  ];
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">YOUR CLOUD, UNDER CONTROL</div>
          <h1>
            Cost operations overview<span className="title-dot">.</span>
          </h1>
          <p>Turn idle capacity into savings you can prove.</p>
        </div>
        <Button onClick={() => navigate("recommendations")}>
          Review recommendations
          <ArrowUpRight size={16} />
        </Button>
      </div>
      <div className="metrics-grid">
        <Metric
          label="Monthly opportunity"
          value={money(monthly, currency)}
          detail={
            monthly === null
              ? "Cost evidence unavailable"
              : `Estimated · ${candidates.length} recommendations · ${currency}`
          }
          icon={<Sparkles size={17} />}
          accent
        />
        <Metric
          label="Verified period savings"
          value={money(verified, savingCurrency)}
          detail={
            verified === null
              ? "No verified measurement period"
              : `${data.fixture ? "Fixture logical financial period" : "Reconciled and final"} · ${savingCurrency}`
          }
          icon={<ShieldCheck size={17} />}
        />
        <Metric
          label="Ready to execute"
          value={
            <>
              {eligible.length}
              <span className="metric-denominator">
                {" "}
                / {data.resources.length}
              </span>
            </>
          }
          detail="Current baseline and safety evidence"
          icon={<Boxes size={17} />}
        />
        <Metric
          label="Active executions"
          value={active.length}
          detail={`${awaiting.length} plans awaiting approval`}
          icon={<Activity size={17} />}
        />
      </div>
      <Panel
        title="Your operating loop"
        eyebrow="FROM EVIDENCE TO OUTCOME"
        action={
          <span className="subtle-label">
            <span className="live-dot" />
            Live control plane
          </span>
        }
      >
        <div className="operating-loop">
          {steps.map((step, index) => (
            <button
              key={step.name}
              className={`loop-step ${step.done ? "done" : ""}`}
              onClick={() => navigate(step.page)}
            >
              <span className="loop-number">
                {step.done ? <CircleCheck size={19} /> : `0${index + 1}`}
              </span>
              <strong>{step.name}</strong>
              <span>{step.detail}</span>
              {index < steps.length - 1 && (
                <ArrowRight className="loop-arrow" size={17} />
              )}
            </button>
          ))}
        </div>
      </Panel>
      <div className="overview-grid">
        <Panel
          title="Next best actions"
          action={
            <span className="count-pill">
              {data.recommendations.length + awaiting.length}
            </span>
          }
        >
          {!data.cloud_accounts.length && (
            <button
              className="action-row"
              onClick={() => navigate("connections")}
            >
              <span className="action-icon">
                <Cloud size={21} />
              </span>
              <span>
                <strong>Connect your first AWS account</strong>
                <small>
                  Read-only discovery is available without execution
                  permissions.
                </small>
              </span>
              <ArrowUpRight size={18} />
            </button>
          )}
          {awaiting.length > 0 && (
            <button
              className="action-row"
              onClick={() => navigate("schedules")}
            >
              <span className="action-icon amber-icon">
                <Fingerprint size={21} />
              </span>
              <span>
                <strong>
                  {awaiting.length} immutable{" "}
                  {awaiting.length === 1 ? "plan needs" : "plans need"} approval
                </strong>
                <small>
                  Review scope, operations, and expiry before authorizing.
                </small>
              </span>
              <ArrowUpRight size={18} />
            </button>
          )}
          {data.recommendations.length > 0 && (
            <button
              className="action-row"
              onClick={() => navigate("recommendations")}
            >
              <span className="action-icon">
                <Timer size={21} />
              </span>
              <span>
                <strong>Schedule non-production idle windows</strong>
                <small>
                  Review workload evidence and create a signed change plan.
                </small>
              </span>
              <ArrowUpRight size={18} />
            </button>
          )}
          {data.executions.some((item) => item.status === "COMPLETED") && (
            <button className="action-row" onClick={() => navigate("savings")}>
              <span className="action-icon">
                <CreditCard size={21} />
              </span>
              <span>
                <strong>Review the financial outcome</strong>
                <small>
                  Separate provisional estimates from verified savings.
                </small>
              </span>
              <ArrowUpRight size={18} />
            </button>
          )}
          {!data.recommendations.length &&
            !awaiting.length &&
            data.cloud_accounts.length > 0 && (
              <div className="panel-inset">
                <Empty
                  title="Ready to find opportunities"
                  text="Generate recommendations using the inventory and workload evidence."
                  action={
                    <Button
                      pending={busy}
                      onClick={() =>
                        void run({
                          path: "/recommendations",
                          body: {},
                          label: "Recommendations generated",
                        })
                      }
                    >
                      Generate recommendations
                    </Button>
                  }
                />
              </div>
            )}
          <div className="safety-footnote">
            <ShieldCheck size={16} />
            <span>
              New stops require fresh signals and an approved plan. Restoration
              stays authorized.
            </span>
          </div>
        </Panel>
        <Panel
          title="Safety posture"
          action={<ShieldCheck className="teal" size={19} />}
        >
          <div className="posture-list">
            <div>
              <span>Control state</span>
              <Badge value={data.org.paused ? "FROZEN" : "READY"}>
                {data.org.paused
                  ? "New stops paused"
                  : "Stops permitted by policy"}
              </Badge>
            </div>
            <div>
              <span>Execution scope</span>
              <strong>Non-production EC2</strong>
            </div>
            <div>
              <span>Approval boundary</span>
              <strong>Per occurrence / scoped policy</strong>
            </div>
            <div>
              <span>Region</span>
              <strong>eu-west-1 · Ireland</strong>
            </div>
            <div>
              <span>Active restoration owners</span>
              <strong>
                {
                  data.executions.filter((item) => item.restoration_owned)
                    .length
                }
              </strong>
            </div>
          </div>
          <div className="posture-bottom">
            <span className="shield-disc">
              <ShieldCheck size={22} />
            </span>
            <div>
              <strong>Safety comes before savings</strong>
              <p>Unknown or stale evidence prevents a stop.</p>
            </div>
          </div>
        </Panel>
      </div>
      <Panel
        title="Recent activity"
        action={
          <TextLink onClick={() => navigate("audit")}>
            View audit trail
          </TextLink>
        }
      >
        {data.audit.length ? (
          <div className="activity-list">
            {data.audit
              .slice()
              .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
              .slice(0, 4)
              .map((item) => (
                <div className="activity-row" key={item.id}>
                  <span className="activity-marker">
                    <CircleCheck size={15} />
                  </span>
                  <div>
                    <strong>{readable(item.action)}</strong>
                    <small>
                      {item.actor} <span>·</span> {item.resource || item.id}
                    </small>
                  </div>
                  <time>{dateTime(item.timestamp)}</time>
                </div>
              ))}
          </div>
        ) : (
          <Empty
            title="Every action leaves a trail"
            text="Connect an account or generate a recommendation to begin the audit history."
          />
        )}
      </Panel>
    </>
  );
}

export default function App() {
  const session = useSyncExternalStore(auth.subscribe, auth.snapshot);
  const [authReady, setAuthReady] = useState(false);
  const [authError, setAuthError] = useState("");
  const [page, setPage] = useState<Page>(pageFromHash);
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [connectionError, setConnectionError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const mutationLock = useRef(false);
  const refreshSequence = useRef(0);
  useEffect(() => {
    void auth
      .initialize()
      .catch((reason) => setAuthError(String(reason.message || reason)))
      .finally(() => setAuthReady(true));
  }, []);
  useEffect(() => {
    const handler = () => {
      setPage(pageFromHash());
      setQuery("");
      setMenuOpen(false);
    };
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  const navigate = (target: Page) => {
    window.location.hash = target;
    setPage(target);
    setQuery("");
    setMenuOpen(false);
  };
  const reload = useCallback(async (showLoading = false) => {
    const sequence = ++refreshSequence.current;
    if (showLoading) setLoading(true);
    try {
      const result = await api.dashboard();
      if (sequence === refreshSequence.current) {
        setData(result);
        setConnectionError("");
        setLastUpdated(new Date());
      }
    } catch (reason) {
      if (sequence === refreshSequence.current)
        setConnectionError(
          reason instanceof Error ? reason.message : String(reason),
        );
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);
  useEffect(() => {
    if (!session) {
      setData(null);
      return;
    }
    void reload(true);
    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") void reload();
    }, 4000);
    return () => window.clearInterval(interval);
  }, [session?.name, reload]);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 6500);
    return () => window.clearTimeout(timer);
  }, [notice]);
  const run: RunMutation = async (mutation) => {
    if (mutationLock.current) return;
    mutationLock.current = true;
    setBusy(true);
    setError("");
    try {
      const result = await api.mutate(
        mutation.path,
        mutation.body || {},
        mutation.version,
      );
      await reload();
      setNotice(mutation.label);
      return result;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      return undefined;
    } finally {
      mutationLock.current = false;
      setBusy(false);
    }
  };
  if (!session)
    return (
      <div className="login-page">
        <div className="login-brand">
          <span className="brand-mark">
            <Command size={25} />
          </span>
          <span>
            cloudcost<span className="brand-light"> / autopilot</span>
          </span>
        </div>
        <div className="login-content">
          <div className="login-visual">
            <div className="login-orbit orbit-one" />
            <div className="login-orbit orbit-two" />
            <div className="login-orbit orbit-three" />
            <span className="login-cloud">
              <Cloud size={64} strokeWidth={1.25} />
            </span>
            <span className="visual-chip chip-one">
              <ShieldCheck size={16} />
              Policy governed
            </span>
            <span className="visual-chip chip-two">
              <Activity size={16} />
              Evidence backed
            </span>
          </div>
          <div className="login-card">
            <div className="eyebrow">CLOUD OPERATIONS, WITH CONFIDENCE</div>
            <h1>
              Less waste.
              <br />
              More control.
            </h1>
            <p>
              Discover idle capacity, approve safe changes, and verify the
              savings. Every action accounted for.
            </p>
            <div className="login-capabilities">
              <span>
                <ShieldCheck size={17} />
                Explicit approvals
              </span>
              <span>
                <FileClock size={17} />
                Complete audit trail
              </span>
              <span>
                <Cloud size={17} />
                EU regional cell
              </span>
            </div>
            {authError && (
              <div role="alert" className="inline-error">
                {authError}
              </div>
            )}
            <Button
              pending={!authReady}
              onClick={() => {
                setAuthError("");
                void auth
                  .login()
                  .catch((reason) => setAuthError(reason.message));
              }}
            >
              Sign in to your workspace
              <ArrowRight size={18} />
            </Button>
            <small className="login-caption">
              Secure sign-in through your organization’s identity provider
            </small>
          </div>
        </div>
        <footer className="login-footer">
          <span>Cloud Cost Autopilot · Operational pilot</span>
          <span>eu-west-1 / Ireland</span>
        </footer>
      </div>
    );
  const selected = navigation.find((item) => item.id === page)!;
  const pageProps = data ? { data, run, busy, query } : null;
  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? "is-open" : ""}`}>
        <a
          className="brand"
          href="#overview"
          aria-label="Cloud Cost Autopilot home"
        >
          <span className="brand-mark">
            <Command size={24} />
          </span>
          <span>
            cloudcost<small>AUTOPILOT</small>
          </span>
        </a>
        <div className="workspace-select">
          <span className="workspace-avatar">
            {data?.org.name?.slice(0, 1) || "F"}
          </span>
          <span>
            <strong>{data?.org.name || "Your workspace"}</strong>
            <small>Operations workspace</small>
          </span>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={`nav-item ${page === item.id ? "selected" : ""}`}
              aria-current={page === item.id ? "page" : undefined}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
              {item.id === "recommendations" &&
                !!data?.recommendations.length && (
                  <span className="nav-count">
                    {data.recommendations.length}
                  </span>
                )}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="regional-note">
            <span className="live-dot" />
            <span>
              EU regional cell<small>eu-west-1 · Ireland</small>
            </span>
            <ShieldCheck size={17} />
          </div>
          <button
            className="user-card"
            onClick={() =>
              void auth.logout().catch((reason) => setError(reason.message))
            }
          >
            <span className="user-avatar">
              {session.name.slice(0, 1).toUpperCase()}
            </span>
            <span>
              <strong>{session.name}</strong>
              <small>Sign out</small>
            </span>
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      {menuOpen && (
        <button
          aria-label="Close navigation"
          className="sidebar-scrim"
          onClick={() => setMenuOpen(false)}
        />
      )}
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              onClick={() => setMenuOpen(true)}
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <span className="breadcrumb-divider">/</span>
            <strong>{selected.label}</strong>
          </div>
          <div className="topbar-right">
            {data?.fixture && (
              <span className="fixture-badge">
                <span />
                FIXTURE MODE
              </span>
            )}
            <span className="region-label">
              <span className="live-dot" />
              EU · Ireland
            </span>
            <button
              className="icon-button"
              aria-label="Open audit trail"
              onClick={() => navigate("audit")}
            >
              <Bell size={18} />
            </button>
            <span className="topbar-avatar">{session.name.slice(0, 1)}</span>
          </div>
        </header>
        <main className="main-content">
          <div className="toolbar">
            <span className="updated-label">
              <span className="live-dot" />
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
                : "Connecting to control plane"}
            </span>
            <div className="toolbar-actions">
              {page !== "overview" && (
                <label className="search-box">
                  <Search size={16} />
                  <input
                    aria-label="Search current view"
                    placeholder="Search this view…"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  {query && (
                    <button
                      aria-label="Clear search"
                      onClick={() => setQuery("")}
                    >
                      <X size={14} />
                    </button>
                  )}
                </label>
              )}
              <button
                className="icon-button refresh-button"
                aria-label="Refresh data"
                disabled={loading || busy}
                onClick={() => void reload(true)}
              >
                <RefreshCw size={16} className={loading ? "spin" : ""} />
              </button>
              {data && (
                <Button
                  secondary={!data.org.paused}
                  danger={!data.org.paused}
                  small
                  pending={busy}
                  onClick={() =>
                    void run({
                      path: "/control/pause",
                      body: { paused: !data.org.paused },
                      version: data.org.version,
                      label: data.org.paused
                        ? "New stops resumed under existing policies"
                        : "New stops paused. Restoration remains active.",
                    })
                  }
                >
                  {data.org.paused ? <Play size={14} /> : <Pause size={14} />}
                  {data.org.paused ? "Resume new stops" : "Pause new stops"}
                </Button>
              )}
            </div>
          </div>
          {(error || connectionError) && (
            <div className="error-banner" role="alert">
              <div>
                <strong>Action needs attention</strong>
                <p>{error || connectionError}</p>
              </div>
              <button
                className="icon-button"
                aria-label="Dismiss error"
                onClick={() => {
                  setError("");
                  setConnectionError("");
                }}
              >
                <X size={18} />
              </button>
            </div>
          )}
          {data?.org.paused && (
            <div className="pause-banner">
              <Pause size={17} />
              <span>
                New stops are paused across this workspace. Owned restoration
                and health checks continue.
              </span>
            </div>
          )}
          {!data ? (
            loading ? (
              <div className="loading-state">
                <RefreshCw size={26} className="spin" />
                <h2>Loading your workspace</h2>
                <p>Reading inventory, evidence, and execution state.</p>
              </div>
            ) : (
              <Empty
                title="The control plane could not be reached"
                text="Check the API and your workspace access, then retry."
                action={
                  <Button onClick={() => void reload(true)}>Try again</Button>
                }
              />
            )
          ) : (
            pageProps && (
              <>
                {page === "overview" && (
                  <Overview
                    data={data}
                    navigate={navigate}
                    run={run}
                    busy={busy}
                  />
                )}
                {page === "workloads" && <WorkloadsPage {...pageProps} />}
                {page === "recommendations" && (
                  <RecommendationsPage {...pageProps} navigate={navigate} />
                )}
                {page === "schedules" && (
                  <SchedulesPage {...pageProps} navigate={navigate} />
                )}
                {page === "executions" && <ExecutionsPage {...pageProps} />}
                {page === "savings" && <SavingsPage {...pageProps} />}
                {page === "allocation" && <CostAllocation {...pageProps} />}
                {page === "connections" && <ConnectionsPage {...pageProps} />}
                {page === "audit" && <AuditPage {...pageProps} />}
              </>
            )
          )}
          <footer className="main-footer">
            <span>
              <ShieldCheck size={14} />
              Evidence preserved. Actions accountable.
            </span>
            <a
              href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html"
              target="_blank"
              rel="noreferrer"
            >
              AWS stop/start behavior
              <ExternalLink size={12} />
            </a>
          </footer>
        </main>
      </div>
      {notice && (
        <div className="toast" role="status">
          <CircleCheck size={19} />
          <span>{notice}</span>
          <button
            aria-label="Dismiss notification"
            onClick={() => setNotice("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
