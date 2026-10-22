// Presentation double only; never imported by the product build.
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { auth } from "../../src/auth";
import { api } from "../../src/api";
import { CommitmentPortfolio } from "../../src/CommitmentPortfolio";
import type { RunMutation } from "../../src/ui";
import "../../src/styles.css";

await auth.initialize();
function Fixture() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run: RunMutation = async ({ path, body, version }) => {
    setBusy(true);
    setError("");
    try { return await api.mutate(path, body, version); }
    catch (error) { setError(error instanceof Error ? error.message : "Unavailable"); }
    finally { setBusy(false); }
  };
  return <main style={{ maxWidth: 1100, margin: "2rem auto", padding: "1rem" }}>
    <h1>Isolated commitment portfolio presentation</h1>
    {error && <p role="alert">{error}</p>}
    <CommitmentPortfolio fixture run={run} busy={busy} />
  </main>;
}
createRoot(document.getElementById("root")!).render(<Fixture />);
