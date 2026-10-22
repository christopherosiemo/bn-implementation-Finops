-- The isolated ingester can attribute persisted execution receipts to financial
-- evidence, but cannot create a stop intent, change ownership or mutate AWS.
GRANT SELECT ON provider_operations TO finops_ingester;
