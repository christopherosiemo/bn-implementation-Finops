// Presentation-only entry point; the application does not import it.
import { createRoot } from "react-dom/client";
import { auth } from "../../src/auth";
import { FleetFixtureRuns } from "../../src/FleetFixtureRuns";
import "../../src/styles.css";

await auth.initialize();
createRoot(document.getElementById("root")!).render(
  <main style={{ maxWidth: 1100, margin: "2rem auto", padding: "1rem" }}>
    <h1>Isolated fixture run presentation</h1>
    <FleetFixtureRuns proposalId="proposal-one" />
  </main>,
);
