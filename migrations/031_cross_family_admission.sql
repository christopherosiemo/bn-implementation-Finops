-- Retain every 018 forward feasibility/failure condition and add the group
-- workload admission boundary. Recovery uses the existing owned inverse path.
CREATE OR REPLACE FUNCTION public.fleet_forward_authority(p_tenant text,p_parent text) RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE p jsonb;control text;BEGIN
 SELECT document INTO p FROM public.fleet_plans WHERE tenant_id=p_tenant AND id=p_parent;PERFORM public.fleet_lock(p_tenant,p->'binding'->>'workload_id');
 SELECT status INTO control FROM public.fleet_controls WHERE tenant_id=p_tenant AND parent_id=p_parent ORDER BY version DESC LIMIT 1;
 IF p IS NULL OR (p->>'expires_at')::timestamptz<=clock_timestamp() OR coalesce(control,'ACTIVE')<>'ACTIVE' OR p->'governance'->>'risk_class'<>'R2' OR p->'governance'->>'enabled'<>'true' THEN RAISE EXCEPTION 'fleet forward authority expired paused or revoked';END IF;
 IF coalesce((p->'budget'->>'maximum_duration_seconds')::integer,0)<1 OR public.fleet_forward_deadline(p) IS NULL OR public.fleet_forward_deadline(p)<=clock_timestamp() OR (SELECT coalesce(sum((s->>'minimum_observation_seconds')::integer),0) FROM jsonb_array_elements(p->'stages') s)>(p->'budget'->>'maximum_duration_seconds')::integer THEN RAISE EXCEPTION 'fleet forward modeled duration exhausted or observations cannot fit';END IF;
 IF public.fleet_cohort_minimum_program_seconds(p) IS NULL OR public.fleet_cohort_minimum_program_seconds(p)>(p->'budget'->>'maximum_duration_seconds')::bigint OR EXISTS(SELECT 1 FROM jsonb_array_elements(p->'proofs') proof WHERE (proof->>'expires_at')::timestamptz<public.fleet_forward_deadline(p)) THEN RAISE EXCEPTION 'fleet intermediate health delivery or immutable authority duration insufficient';END IF;
 IF EXISTS(SELECT 1 FROM public.fleet_cohort_failures failure JOIN public.fleet_executions execution ON execution.tenant_id=failure.tenant_id AND execution.id=failure.execution_id WHERE execution.tenant_id=p_tenant AND execution.parent_id=p_parent) THEN RAISE EXCEPTION 'fleet permanent safety failure disqualifies forward work and positive savings';END IF;
 IF NOT public.fleet_group_admission(p_tenant,p->'binding'->>'workload_id','V4',NULL) THEN RAISE EXCEPTION 'fleet workload has an unresolved cross-family obligation';END IF;
 RETURN p;
END $$;
