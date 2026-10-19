// Test-only server. No entry point from tests/fixtures enters the Vite build.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

export const presentationOrigin='http://127.0.0.1:4177';
export function presentationOptions(){
 return {
  configFile:false,envFile:false,envDir:false,envPrefix:'__DISABLED_PRESENTATION_ENV_',
  root:path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),
  define:{'import.meta.env.VITE_OIDC_ISSUER':JSON.stringify(presentationOrigin+'/__presentation_oidc'),'import.meta.env.VITE_OIDC_CLIENT_ID':JSON.stringify('presentation-only')},
  server:{host:'127.0.0.1',port:4177,strictPort:true,hmr:false,proxy:{},fs:{strict:true,allow:[path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..')]}}
 };
}
export function presentationRequestAllowed(request){
 return request.headers?.host==='127.0.0.1:4177'&&['127.0.0.1','::ffff:127.0.0.1'].includes(request.socket?.remoteAddress);
}
export async function startPresentationServer(){
 assert.equal(process.argv.length,2,'No alternate presentation server targets accepted');
 const [{createServer},{default:react}]=await Promise.all([import('vite'),import('@vitejs/plugin-react')]);
 const server=await createServer({...presentationOptions(),plugins:[react(),{
  name:'presentation-network-boundary',configureServer(vite){vite.middlewares.use((request,response,next)=>{
   if(!presentationRequestAllowed(request)){response.statusCode=403;response.end('ISOLATED_PRESENTATION_ONLY');return;}
   const target=new URL(request.url||'/',presentationOrigin);
   if(target.pathname==='/__presentation_health'){response.setHeader('Content-Type','text/plain');response.end('ISOLATED_PRESENTATION_ONLY');return;}
   if(target.pathname.startsWith('/v1/')||target.pathname.startsWith('/__presentation_oidc')){
    response.statusCode=502;response.setHeader('Content-Type','application/json');response.end('{"error":"UNMOCKED_PRESENTATION_REQUEST"}');return;
   }
   next();
  });}
 }]});
 let closing=false;
 const close=async()=>{if(closing)return;closing=true;await server.close();process.exitCode=0;};
 process.once('SIGINT',close);process.once('SIGTERM',close);
 await server.listen();
 const address=server.httpServer?.address();assert.ok(address&&typeof address==='object'&&address.address==='127.0.0.1'&&address.port===4177);
 return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)startPresentationServer().catch(()=>{console.error('Isolated presentation server refused.');process.exitCode=1;});
