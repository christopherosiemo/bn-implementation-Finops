-- A source reader must serialize authority with registration revocation without
-- gaining permission to update registrations. Source sync has a separate shared
-- advisory guard, acquired by the service before this narrowly scoped row lock.
CREATE FUNCTION financial_source_current_lock(p_tenant text,p_source text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_tenant IS NULL OR p_tenant='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR p_source IS NULL OR p_source='' THEN
  RAISE EXCEPTION 'financial source tenant or identity mismatch';
 END IF;
 PERFORM 1 FROM public.source_registrations WHERE tenant_id=p_tenant AND id=p_source FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION financial_source_current_lock(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION financial_source_current_lock(text,text) TO finops_api,finops_worker,finops_signer,finops_executor;
