// Presentation-only entry point, never imported by the console application.
import { createRoot } from "react-dom/client";
import { auth } from "../../src/auth";
import { FleetGroupAuthorization } from "../../src/FleetGroupAuthorization";
import "../../src/styles.css";

await auth.initialize();
const params = new URLSearchParams(window.location.search);
createRoot(document.getElementById("root")!).render(
  <main style={{ maxWidth: 1100, margin: "2rem auto", padding: "1rem" }}>
    <h1>Explicit isolated authorization presentation fixture</h1>
    <FleetGroupAuthorization
      proposalId={params.get("proposal") || "proposal-one"}
    />
  </main>,
);
