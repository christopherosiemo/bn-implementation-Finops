-- Run interactively as the RDS administrator over verified TLS before Helm.
-- Passwords are deliberately absent. Set each with psql \password afterwards.
-- This file is initial provisioning, not an idempotent schema migration.
CREATE ROLE finops_api NOLOGIN;
CREATE ROLE finops_worker NOLOGIN;
CREATE ROLE finops_ingester NOLOGIN;
CREATE ROLE finops_signer NOLOGIN;
CREATE ROLE finops_executor NOLOGIN;
CREATE ROLE finops_activity NOLOGIN;
CREATE ROLE finops_migrator LOGIN CREATEROLE;
CREATE ROLE finops_api_login LOGIN IN ROLE finops_api;
CREATE ROLE finops_worker_login LOGIN IN ROLE finops_worker;
CREATE ROLE finops_ingester_login LOGIN IN ROLE finops_ingester;
CREATE ROLE finops_signer_login LOGIN IN ROLE finops_signer;
CREATE ROLE finops_executor_login LOGIN IN ROLE finops_executor;
CREATE ROLE finops_activity_login LOGIN IN ROLE finops_activity;
CREATE ROLE finops_temporal LOGIN;
GRANT CONNECT ON DATABASE finops TO finops_migrator, finops_api_login, finops_worker_login, finops_ingester_login, finops_signer_login, finops_executor_login, finops_activity_login;
GRANT CREATE ON SCHEMA public TO finops_migrator;
GRANT USAGE ON SCHEMA public TO finops_migrator WITH GRANT OPTION;
CREATE DATABASE temporal OWNER finops_temporal;
CREATE DATABASE temporal_visibility OWNER finops_temporal;
