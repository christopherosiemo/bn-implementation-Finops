const issuer = (
  import.meta.env.VITE_OIDC_ISSUER || "http://localhost:8081/realms/finops"
).replace(/\/$/, "");
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID || "console";
const redirectUri = () => `${window.location.origin}/`;
type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
};
type Session = {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_at: number;
  name: string;
};
let session: Session | null = null;
let discovery: Promise<Discovery> | undefined;
let initialization: Promise<void> | undefined;
let refreshing: Promise<string> | undefined;
const listeners = new Set<() => void>();
const publish = () => listeners.forEach((listener) => listener());
const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const metadata = () =>
  (discovery ||= fetch(`${issuer}/.well-known/openid-configuration`).then(
    async (response) => {
      if (!response.ok)
        throw new Error(
          "Identity provider is unavailable. Check Keycloak and try again.",
        );
      return response.json() as Promise<Discovery>;
    },
  ));

function saveToken(value: {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
}) {
  let name = "Operator";
  try {
    const payload = JSON.parse(
      atob(
        value.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"),
      ),
    );
    name = payload.name || payload.preferred_username || name;
  } catch {
    /* Display name is optional. */
  }
  session = {
    ...value,
    expires_at: Date.now() + value.expires_in * 1000,
    name,
  };
  publish();
}

export const auth = {
  subscribe(listener: () => void) {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
  snapshot: () => session,
  async initialize() {
    return (initialization ||= (async () => {
      const query = new URLSearchParams(window.location.search);
      if (!query.has("code") && !query.has("error")) return;
      const expected = sessionStorage.getItem("finops.oidc.state");
      const verifier = sessionStorage.getItem("finops.oidc.verifier");
      sessionStorage.removeItem("finops.oidc.state");
      sessionStorage.removeItem("finops.oidc.verifier");
      window.history.replaceState(
        {},
        "",
        `${window.location.pathname}${window.location.hash}`,
      );
      if (query.has("error"))
        throw new Error(
          `Sign-in failed: ${query.get("error_description") || query.get("error")}`,
        );
      if (!expected || expected !== query.get("state") || !verifier)
        throw new Error("Sign-in state did not match. Please sign in again.");
      const config = await metadata();
      const response = await fetch(config.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          redirect_uri: redirectUri(),
          code: query.get("code")!,
          code_verifier: verifier,
        }),
      });
      if (!response.ok)
        throw new Error("Could not complete sign-in. Please try again.");
      saveToken(await response.json());
    })());
  },
  async login() {
    const config = await metadata();
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(48)));
    const state = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const challenge = base64url(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(verifier),
        ),
      ),
    );
    sessionStorage.setItem("finops.oidc.verifier", verifier);
    sessionStorage.setItem("finops.oidc.state", state);
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri(),
      response_type: "code",
      scope: "openid profile email",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    window.location.assign(`${config.authorization_endpoint}?${query}`);
  },
  async token(): Promise<string> {
    if (!session) throw new Error("Sign in to continue.");
    if (session.expires_at > Date.now() + 30_000) return session.access_token;
    if (!session.refresh_token) {
      session = null;
      publish();
      throw new Error("Your session has expired. Please sign in again.");
    }
    return (refreshing ||= (async () => {
      try {
        const config = await metadata();
        const response = await fetch(config.token_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: clientId,
            refresh_token: session!.refresh_token!,
          }),
        });
        if (!response.ok) {
          session = null;
          publish();
          throw new Error("Your session has expired. Please sign in again.");
        }
        saveToken(await response.json());
        return session!.access_token;
      } finally {
        refreshing = undefined;
      }
    })());
  },
  async logout() {
    const idToken = session?.id_token;
    session = null;
    publish();
    const config = await metadata();
    if (config.end_session_endpoint) {
      const query = new URLSearchParams({
        client_id: clientId,
        post_logout_redirect_uri: redirectUri(),
      });
      if (idToken) query.set("id_token_hint", idToken);
      window.location.assign(`${config.end_session_endpoint}?${query}`);
    }
  },
};
