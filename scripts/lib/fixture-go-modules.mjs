// Only module lockfiles enter this outbound, credential-free preparation step.
// Actual acceptance processes retain their internal-only network and credentials.
import assert from 'node:assert/strict';
import {chmodSync,copyFileSync,lstatSync,mkdirSync,realpathSync} from 'node:fs';
import path from 'node:path';

const namePattern=/^[a-z][a-z0-9-]{0,110}$/;
export function validateFixtureGoCache(object,name,labelKey,runID){assert.match(name,namePattern);assert.equal(object.Name,name);assert.equal(object.Labels?.[labelKey],runID);assert.equal(object.Driver,'local');assert.equal(Object.keys(object.Options||{}).length,0,'Host-backed cache overrides refused');}
export function createFixtureGoCache(run,name,labelKey,runID){assert.match(name,namePattern);run(['volume','create','--driver','local','--label',labelKey+'='+runID,name]);const object=JSON.parse(run(['volume','inspect',name]))[0];validateFixtureGoCache(object,name,labelKey,runID);}
export function removeFixtureGoCache(run,name,labelKey,runID){const names=run(['volume','ls','--filter','name=^'+name+'$','--format','{{.Name}}']).split('\n');if(!names.includes(name))return;const object=JSON.parse(run(['volume','inspect',name]))[0];validateFixtureGoCache(object,name,labelKey,runID);run(['volume','rm',name]);}

export function prepareFixtureGoModules(run,{imageID,sourceDirectory,privateDirectory,moduleVolume,labelKey,runID,containerName}){
 assert.match(imageID,/^sha256:[a-f0-9]{64}$/);assert.match(moduleVolume,namePattern);assert.match(containerName,namePattern);assert.match(labelKey,/^finops\.[a-z0-9.-]+$/);assert.match(runID,/^[a-f0-9-]{36}$/);
 const directory=path.join(privateDirectory,'module-locks');mkdirSync(directory,{mode:0o700});const relative=path.relative(realpathSync(privateDirectory),realpathSync(directory));assert.equal(relative,'module-locks');
 for(const name of ['go.mod','go.sum']){const source=path.join(sourceDirectory,name);const stat=lstatSync(source);assert.ok(stat.isFile()&&!stat.isSymbolicLink());copyFileSync(source,path.join(directory,name));chmodSync(path.join(directory,name),0o444);}chmodSync(directory,0o555);
 let failure;
 try {
  run(['run','--rm','--name',containerName,'--label',labelKey+'='+runID,'--pull','never','--network','bridge','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','1024m','--cpus','2','-e','GOTOOLCHAIN=local','-e','GOCACHE=/tmp/go-build-cache','-e','HOME=/tmp/empty-home','-e','GIT_CONFIG_NOSYSTEM=1','-e','GIT_TERMINAL_PROMPT=0','-e','AWS_EC2_METADATA_DISABLED=true','--mount','type=bind,src='+directory+',dst=/modules,readonly','--mount','type=volume,src='+moduleVolume+',dst=/go/pkg/mod','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=256m','--workdir','/modules',imageID,'sh','-c','mkdir -p /tmp/empty-home && go mod download'],{timeout:300_000});
 }catch(error){failure=error;}
 // A killed Docker client can leave its --rm container running. Query the
 // pinned daemon successfully before treating absence as successful cleanup.
 const present=run(['ps','--all','--filter','name=^/'+containerName+'$','--format','{{.Names}}']).split('\n');
 if(present.includes(containerName)){const object=JSON.parse(run(['inspect','--type','container',containerName]))[0];assert.equal(object.Name?.replace(/^\//,''),containerName);assert.equal(object.Config?.Labels?.[labelKey],runID);assert.equal(object.HostConfig?.NetworkMode,'bridge');assert.equal(object.HostConfig?.Privileged,false);assert.equal(Object.keys(object.HostConfig?.PortBindings||{}).length,0);run(['rm','--force',containerName]);}
 if(failure)throw failure;
}
