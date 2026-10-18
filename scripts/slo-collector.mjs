// Build only source-bound, explicitly observed SLI minutes. No percentile input
// or missing-value default can establish health on the receiving service.
const MAX_COUNT = 1_000_000_000_000;
const fields = ['interval_start', 'interval_end', 'request_count', 'error_count', 'availability_good_seconds', 'availability_total_seconds', 'latency'];
function exactKeys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || allowed.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !allowed.includes(key))) throw new Error(`${label} requires only explicit supported fields`);
}
function count(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COUNT) throw new Error(`${label} must be an explicit bounded nonnegative integer`);
}

export function buildSLOInterval(observation, config, sequence, now = new Date()) {
  exactKeys(observation, fields, 'SLO observation');
  for (const key of ['source_id', 'resource_id', 'workload_id', 'objective_id']) if (typeof config[key] !== 'string' || !config[key].trim()) throw new Error('Registered SLO source/resource/workload/objective binding required');
  if (!Number.isSafeInteger(sequence) || sequence <= 0) throw new Error('SLO sequence must be a positive safe integer');
  const start = new Date(observation.interval_start), end = new Date(observation.interval_end);
  if (typeof observation.interval_start !== 'string' || typeof observation.interval_end !== 'string' || !/(?:Z|\+00:00)$/.test(observation.interval_start) || !/(?:Z|\+00:00)$/.test(observation.interval_end) || !Number.isFinite(start.getTime()) || !Number.isFinite(now.getTime()) || end - start !== 60_000 || start.getTime() % 60_000 || end > now || now - end > 120_000) throw new Error('SLO observation is not a recent complete UTC minute');
  for (const key of ['request_count', 'error_count', 'availability_good_seconds', 'availability_total_seconds']) count(observation[key], key);
  if (observation.error_count > observation.request_count || observation.availability_total_seconds !== 60 || observation.availability_good_seconds > 60) throw new Error('SLO error/availability counts do not match their denominators');
  const histogram = observation.latency;
  exactKeys(histogram, ['unit', 'sample_count', 'buckets'], 'SLO histogram');
  count(histogram.sample_count, 'SLO latency sample_count');
  if (histogram.unit !== 'milliseconds' || histogram.sample_count !== observation.request_count || !Array.isArray(histogram.buckets) || histogram.buckets.length < 1 || histogram.buckets.length > 256) throw new Error('SLO histogram requires disjoint millisecond buckets and request-matched samples');
  let total = 0, previous = -1;
  const buckets = histogram.buckets.map((bucket, index) => {
    exactKeys(bucket, ['upper_bound_ms', 'count'], 'SLO histogram bucket');
    count(bucket.count, 'SLO bucket count');
    total += bucket.count;
    if (!Number.isSafeInteger(total) || total > MAX_COUNT) throw new Error('SLO histogram count exceeds the bounded total');
    const last = index === histogram.buckets.length - 1;
    if (bucket.upper_bound_ms === null) {
      if (!last) throw new Error('SLO unbounded histogram bucket must be last');
    } else {
      if (last || !Number.isSafeInteger(bucket.upper_bound_ms) || bucket.upper_bound_ms < 0 || bucket.upper_bound_ms > 86_400_000 || bucket.upper_bound_ms <= previous) throw new Error('SLO histogram bounds must increase and end with null');
      previous = bucket.upper_bound_ms;
    }
    return { upper_bound_ms: bucket.upper_bound_ms, count: bucket.count };
  });
  if (total !== histogram.sample_count) throw new Error('SLO histogram disjoint counts must equal sample_count');
  return {
    schema_version: '1', source_id: config.source_id, resource_id: config.resource_id, workload_id: config.workload_id, objective_id: config.objective_id, sequence,
    interval_start: start.toISOString(), interval_end: end.toISOString(), request_count: observation.request_count, error_count: observation.error_count,
    availability_good_seconds: observation.availability_good_seconds, availability_total_seconds: observation.availability_total_seconds,
    latency: { unit: 'milliseconds', sample_count: histogram.sample_count, buckets },
  };
}
