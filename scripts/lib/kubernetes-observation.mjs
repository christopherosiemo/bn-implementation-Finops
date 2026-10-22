// The local controller double must observe real nonterminating pod topology
// before ACK. This is not a replacement for the strict native VerifySync gate.
export function boundedRolloutSnapshot(snapshot) {
  const d = snapshot?.deployment ?? {};
  return {
    collected_at: snapshot?.collected_at,
    deployment: Object.fromEntries(['uid', 'generation', 'observed_generation', 'replicas', 'ready_replicas', 'updated_replicas', 'unavailable_replicas', 'paused', 'deleting', 'spec_hash'].map(key => [key, d[key]])),
    pods: (Array.isArray(snapshot?.pods) ? snapshot.pods : []).slice(0, 100).map(pod => Object.fromEntries(['uid', 'node', 'zone', 'ready', 'terminating', 'restarts', 'oom_killed'].map(key => [key, pod[key]]))),
    nodes: (Array.isArray(snapshot?.nodes) ? snapshot.nodes : []).slice(0, 100).map(node => Object.fromEntries(['uid', 'name', 'zone', 'ready', 'unschedulable'].map(key => [key, node[key]]))),
    problems: (Array.isArray(snapshot?.problems) ? snapshot.problems : []).slice(0, 25),
  };
}

export function rolloutObservation(snapshot, now, expectedSpecHash) {
  if (!snapshot || !Array.isArray(snapshot.problems) || snapshot.problems.length) return { ready: false, fatal: 'K8S_OBSERVATION_NATIVE_PROBLEMS' };
  if (expectedSpecHash && snapshot.deployment?.spec_hash !== expectedSpecHash) return { ready: false, fatal: 'K8S_OBSERVATION_SPEC_DRIFT' };
  const pods = snapshot.pods;
  if (!Array.isArray(pods)) return { ready: false, fatal: 'K8S_OBSERVATION_PODS_UNKNOWN' };
  if (pods.some(pod => pod.oom_killed || pod.restarts > 0)) return { ready: false, fatal: 'K8S_OBSERVATION_RECOVERY_REQUIRES_REVIEW' };
  const active = pods.filter(pod => pod.terminating === false);
  const d = snapshot.deployment ?? {};
  const at = Date.parse(snapshot.collected_at);
  const ready = Number.isFinite(at) && at <= now + 5000 && at >= now - 120000
    && Number.isInteger(d.replicas) && d.replicas >= 2 && !d.paused && !d.deleting
    && Number.isInteger(d.generation) && d.observed_generation >= d.generation
    && d.ready_replicas === d.replicas && d.updated_replicas === d.replicas && d.unavailable_replicas === 0
    && active.length === d.replicas && active.every(pod => pod.ready === true && typeof pod.uid === 'string' && pod.uid && typeof pod.zone === 'string' && pod.zone)
    && new Set(active.map(pod => pod.uid)).size === active.length && new Set(active.map(pod => pod.zone)).size >= 2;
  return { ready, fatal: null };
}

export async function waitForNativeRollout({ collect, expectedSpecHash, onFailure, timeout = 90000, now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  if (!Number.isInteger(timeout) || timeout <= 0 || timeout > 300000) throw new Error('K8S_OBSERVATION_TIMEOUT_INVALID');
  const deadline = now() + timeout;
  let last;
  while (true) {
    try { last = collect(); } catch (error) {
      onFailure?.(boundedRolloutSnapshot(last));
      throw error; // Transport/auth/native errors are never blanket-retried.
    }
    const result = rolloutObservation(last, now(), expectedSpecHash);
    if (result.ready) return last;
    if (result.fatal || now() >= deadline) {
      onFailure?.(boundedRolloutSnapshot(last));
      throw new Error(result.fatal ?? 'K8S_OBSERVATION_TOPOLOGY_TIMEOUT');
    }
    await sleep(1000);
  }
}
