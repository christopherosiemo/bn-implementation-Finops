// Presentation-only entry point. Never imported by the application build.
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { auth } from "../../src/auth";
import { api } from "../../src/api";
import { FleetJointDecision } from "../../src/FleetJointDecision";
import type { RunMutation } from "../../src/ui";
import "../../src/styles.css";

await auth.initialize();
function Fixture() {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const run: RunMutation = async ({ path, body, version }) => {
    setError("");
    setBusy(true);
    try {
      return await api.mutate(path, body, version);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unavailable");
    } finally {
      setBusy(false);
    }
  };
  return (
    <main style={{ maxWidth: 1100, margin: "2rem auto", padding: "1rem" }}>
      <h1>Isolated joint fleet decision presentation</h1>
      {error && <p role="alert">{error}</p>}
      <FleetJointDecision
        workload="workload-one"
        fixture
        run={run}
        busy={busy}
      />
    </main>
  );
}
createRoot(document.getElementById("root")!).render(<Fixture />);
