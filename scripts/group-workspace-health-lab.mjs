// Opt-in local recovered-health acceptance. The shared host retains fixed
// source/image/target isolation; this entry accepts no runtime arguments.
import {groupWorkspaceRecoveryHealthLab} from './group-workspace-reconstruction-lab.mjs';
groupWorkspaceRecoveryHealthLab().catch(()=>{
 console.error('Recovered health acceptance failed; source, state, credentials and recovery bundles remain private.');
 process.exitCode=1;
});
