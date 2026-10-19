// Explicit operator upgrade material. Never connects or applies SQL.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {materializeDecisionCredentialBinding} from './bootstrap-fleet-decision.mjs';

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  assert.equal(process.argv.length,2);assert.equal(process.env.FLEET_DECISION_ENABLED,'true');
  const result=materializeDecisionCredentialBinding(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),{
   tenant:process.env.FLEET_DECISION_TENANT_ID,
   mode:process.env.FLEET_DECISION_DATABASE_MODE??'LOCAL_PRIVATE',
   host:process.env.FLEET_DECISION_BOOTSTRAP_DATABASE_HOST??'postgres',
   database:process.env.FLEET_DECISION_BOOTSTRAP_DATABASE_NAME??'finops',
   expectedRoleOID:process.env.FLEET_DECISION_CREDENTIAL_ROLE_OID,
  });
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch{process.stderr.write('FLEET_DECISION_CREDENTIAL_BINDING_REFUSED\n');process.exitCode=1;}
}
