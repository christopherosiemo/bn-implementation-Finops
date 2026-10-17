import { Check, ChevronRight, CircleHelp, LoaderCircle, X } from "lucide-react";
import {
  useEffect,
  useRef,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import type { Document } from "./types";
import type { Saving } from "./types";

export function Button({
  children,
  secondary = false,
  danger = false,
  small = false,
  pending = false,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  secondary?: boolean;
  danger?: boolean;
  small?: boolean;
  pending?: boolean;
}) {
  return (
    <button
      className={`button ${secondary ? "secondary" : ""} ${danger ? "danger" : ""} ${small ? "small" : ""} ${className}`}
      {...props}
      disabled={pending || props.disabled}
      aria-busy={pending}
    >
      {pending && <LoaderCircle size={15} className="spin" />}
      {children}
    </button>
  );
}
export const readable = (value: unknown): string =>
  value === undefined || value === null || value === ""
    ? "Not available"
    : typeof value === "string"
      ? value
          .replace(/_/g, " ")
          .toLowerCase()
          .replace(/^./, (c) => c.toUpperCase())
      : typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
export const shortId = (id?: string) =>
  id ? (id.length > 25 ? `${id.slice(0, 12)}…${id.slice(-6)}` : id) : "—";
export const dateTime = (date?: string) => {
  if (!date) return "—";
  const parsed = new Date(date);
  return Number.isNaN(parsed.getTime())
    ? date
    : new Intl.DateTimeFormat("en-GB", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(parsed);
};
export function money(value: unknown, currency = "GBP"): string {
  const numeric = Number(value);
  if (value === undefined || value === null || !Number.isFinite(numeric))
    return "—";
  try {
    return new Intl.NumberFormat("en-GB", {
      style: "currency",
      currency,
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(numeric);
  } catch {
    return `${numeric.toFixed(2)} ${currency}`;
  }
}
export function sumMoney(values: unknown[]): string {
  let total = 0n;
  for (const value of values) {
    const match = /^(-?)(\d+)(?:\.(\d{1,12}))?$/.exec(String(value ?? "0"));
    if (!match) continue;
    const amount =
      BigInt(match[2]) * 1_000_000_000_000n +
      BigInt((match[3] || "").padEnd(12, "0"));
    total += match[1] ? -amount : amount;
  }
  const absolute = total < 0n ? -total : total;
  return `${total < 0n ? "-" : ""}${absolute / 1_000_000_000_000n}.${String(absolute % 1_000_000_000_000n).padStart(12, "0")}`;
}
export function currentSavings(records: Saving[]): Saving[] {
  const superseded = new Set(
    records.map((record) => record.supersedes_id).filter(Boolean),
  );
  return records.filter(
    (record) => record.is_current !== false && !superseded.has(record.id),
  );
}
export function Badge({
  value,
  children,
  tone,
}: {
  value?: unknown;
  children?: ReactNode;
  tone?: string;
}) {
  const status = String(value || "").toUpperCase();
  const color =
    tone ||
    (/FAIL|BLOCK|ERROR|ACTIVE|UNHEALTHY|UNKNOWN|FROZEN/.test(status)
      ? "red"
      : /PENDING|PROVISIONAL|RECOMMEND|WAIT|RESTOR|STOPPING|STARTING/.test(
            status,
          )
        ? "amber"
        : /ELIGIBLE|READY|CLEAR|VERIFIED|SUCCESS|COMPLET|APPROVED|CONNECTED|HEALTHY|RUNNING/.test(
              status,
            )
          ? "green"
          : "neutral");
  return (
    <span className={`badge ${color}`}>
      <span className="badge-dot" />
      {children || readable(value)}
    </span>
  );
}
export function Empty({
  title,
  text,
  action,
}: {
  title: string;
  text: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <CircleHelp size={23} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
export function Panel({
  title,
  eyebrow,
  action,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-head">
          <div>
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            <h2>{title}</h2>
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function Metric({
  label,
  value,
  detail,
  icon,
  accent = false,
}: {
  label: string;
  value: ReactNode;
  detail: string;
  icon?: ReactNode;
  accent?: boolean;
}) {
  return (
    <div className={`metric ${accent ? "metric-accent" : ""}`}>
      <div className="metric-label">
        {label}
        {icon}
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}
export function Modal({
  title,
  subtitle,
  children,
  onClose,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLElement>(null);
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialog.current
      ?.querySelector<HTMLElement>("button, input, select")
      ?.focus();
    return () => {
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialog}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onKeyDown={(event) => {
          if (event.key === "Escape") onClose();
          if (event.key !== "Tab") return;
          const focusable = Array.from(
            dialog.current?.querySelectorAll<HTMLElement>(
              'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), summary, [tabindex="0"]',
            ) || [],
          );
          const first = focusable[0];
          const last = focusable.at(-1);
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
          }
        }}
      >
        <div className="modal-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}
export function Evidence({
  record,
  onClose,
}: {
  record: Document;
  onClose: () => void;
}) {
  return (
    <Modal
      title="Evidence & record"
      subtitle={`${record.id} · version ${record.version}`}
      onClose={onClose}
    >
      <div className="evidence-note">
        <Check size={16} /> Source values are preserved below for review.
      </div>
      <pre className="json-evidence">{JSON.stringify(record, null, 2)}</pre>
    </Modal>
  );
}
export function TextLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-link" onClick={onClick}>
      {children}
      <ChevronRight size={14} />
    </button>
  );
}
export function Table({
  headings,
  children,
}: {
  headings: string[];
  children: ReactNode;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            {headings.map((heading) => (
              <th scope="col" key={heading}>
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
export function matches(query: string, ...values: unknown[]) {
  return (
    !query.trim() ||
    values.some((value) =>
      String(value || "")
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
    )
  );
}
export type Mutation = {
  path: string;
  body?: unknown;
  version?: number;
  label: string;
};
export type RunMutation = (mutation: Mutation) => Promise<Document | undefined>;
