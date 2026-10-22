import { auth } from "./auth";
import type { Dashboard, Document, WireDashboard } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly reasonCode?: string,
  ) {
    super(message);
  }
}

const pendingKeys = new Map<string, string>();
async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
  version?: number,
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${await auth.token()}`,
  };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    const signature = JSON.stringify([path, body, version]);
    const key = pendingKeys.get(signature) || crypto.randomUUID();
    pendingKeys.set(signature, key);
    headers["Idempotency-Key"] = key;
    if (version !== undefined) headers["If-Match"] = `"${version}"`;
  }
  const response = await fetch(`/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  let result: unknown;
  try {
    result = text ? JSON.parse(text) : undefined;
  } catch {
    throw new ApiError(
      "The API returned an unreadable response. Check the service logs.",
      response.status,
    );
  }
  if (!response.ok) {
    if (method !== "GET" && response.status < 500)
      pendingKeys.delete(JSON.stringify([path, body, version]));
    const error = result as
      | {
          message?: string;
          error?: string | { message?: string };
          reason_code?: string;
        }
      | undefined;
    const message =
      error?.message ||
      (typeof error?.error === "string"
        ? error.error
        : error?.error?.message) ||
      `Request failed (${response.status}).`;
    throw new ApiError(
      response.status === 409 || response.status === 412
        ? `${message} Refresh the view and retry.`
        : message,
      response.status,
      error?.reason_code,
    );
  }
  if (method !== "GET")
    pendingKeys.delete(JSON.stringify([path, body, version]));
  return result as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  dashboard: async () => {
    const result = await request<WireDashboard>("/dashboard");
    const collections = [
      "cloud_accounts",
      "resources",
      "workloads",
      "recommendations",
      "policies",
      "schedules",
      "change_plans",
      "executions",
      "savings",
      "audit",
      "data_quality",
    ] as const;
    if (!result?.org || collections.some((key) => !Array.isArray(result[key])))
      throw new ApiError(
        "The API returned an incomplete dashboard. Check tenant initialization and database migrations.",
        502,
      );
    return result as Dashboard;
  },
  mutate: <T = Document>(path: string, body: unknown = {}, version?: number) =>
    request<T>(path, "POST", body, version),
};
