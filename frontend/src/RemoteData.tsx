import { useEffect, useState, type ReactNode } from "react";
import { api } from "./api";
import { Button, Empty } from "./ui";

export function useRemote<T>(path: string | null, refresh = 0) {
  const [state, setState] = useState<{
    path: string | null;
    value?: T;
    error?: string;
    loading: boolean;
  }>({ path, loading: Boolean(path) });
  useEffect(() => {
    let active = true;
    if (!path) {
      setState({ path, loading: false });
      return;
    }
    setState({ path, loading: true });
    void api.get<T>(path).then(
      (value) => {
        if (active) setState({ path, value, loading: false });
      },
      (error: unknown) => {
        if (active)
          setState({
            path,
            loading: false,
            error:
              error instanceof Error
                ? error.message
                : "The source could not be read.",
          });
      },
    );
    return () => {
      active = false;
    };
  }, [path, refresh]);
  return state.path === path
    ? state
    : { path, loading: Boolean(path), value: undefined, error: undefined };
}

// Mount with a query/revision key when refreshing; cursor values stay opaque and
// are appended only to the same authorized query, never inferred from row IDs.
export function RemotePage<T extends { id: string }>({
  path,
  label,
  empty,
  children,
}: {
  path: string;
  label: string;
  empty: string;
  children: (items: T[]) => ReactNode;
}) {
  const first = useRemote<{ items: T[]; next_cursor: string | null }>(path);
  const [pages, setPages] = useState<
    { items: T[]; next_cursor: string | null }[]
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const page = pages.at(-1) ?? first.value;
  const items = [first.value, ...pages].flatMap((entry) => entry?.items ?? []);
  if (first.loading)
    return (
      <p role="status" className="form-note">
        Loading {label.toLowerCase()}…
      </p>
    );
  if (first.error)
    return (
      <p role="alert" className="blocker-text">
        {label} unavailable. {first.error}
      </p>
    );
  if (
    !first.value ||
    !Array.isArray(first.value.items) ||
    !(
      first.value.next_cursor === null ||
      typeof first.value.next_cursor === "string"
    )
  )
    return (
      <p role="alert" className="blocker-text">
        {label} unavailable. The API returned an incomplete page.
      </p>
    );
  return (
    <>
      {items.length ? (
        children(items)
      ) : (
        <Empty title={`No ${label.toLowerCase()}`} text={empty} />
      )}
      {error && (
        <p role="alert" className="blocker-text">
          {error}
        </p>
      )}
      {page?.next_cursor && (
        <div className="remote-page-actions">
          <Button
            type="button"
            secondary
            small
            pending={loading}
            onClick={async () => {
              setLoading(true);
              setError("");
              try {
                const separator = path.includes("?") ? "&" : "?";
                const next = await api.get<{
                  items: T[];
                  next_cursor: string | null;
                }>(
                  `${path}${separator}cursor=${encodeURIComponent(page.next_cursor!)}`,
                );
                if (
                  !Array.isArray(next.items) ||
                  !(
                    next.next_cursor === null ||
                    typeof next.next_cursor === "string"
                  ) ||
                  next.next_cursor === page.next_cursor ||
                  next.items.some((item) =>
                    items.some((old) => old.id === item.id),
                  )
                )
                  throw new Error(
                    "The API returned an incomplete or repeated page. Refresh before continuing.",
                  );
                setPages((current) => [...current, next]);
              } catch (error) {
                setError(
                  error instanceof Error
                    ? error.message
                    : "Could not read the next page.",
                );
              } finally {
                setLoading(false);
              }
            }}
          >
            Load more {label.toLowerCase()}
          </Button>
        </div>
      )}
    </>
  );
}
