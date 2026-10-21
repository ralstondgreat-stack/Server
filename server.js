'use strict';
// ParentGuard relay API. Deploy behind a managed HTTPS reverse proxy (TLS required).
// In-memory MVP: pairing/session data resets on restart. Add a persistent database before production.
const http = require('http');
const crypto = require('crypto');
const PORT = Number(process.env.PORT || 8080);
const devices = new Map();
const pairCodes = new Map();
const parentTokens = new Map();
const claimAttempts = new Map();
const MAX_BODY = 2 * 1024 * 1024;
const now = () => Date.now();
const token = () => crypto.randomBytes(32).toString('base64url');
const code = () => String(crypto.randomInt(100000, 1000000));
function send(res, status, obj) { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(status, {'content-type':'application/json; charset=utf-8','content-length':b.length,'cache-control':'no-store','x-content-type-options':'nosniff'}); res.end(b); }
function read(req) { return new Promise((resolve,reject)=>{ let chunks=[], size=0; req.on('data',c=>{size+=c.length;if(size>MAX_BODY){reject(new Error('body too large'));req.destroy();}else chunks.push(c);}); req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}'));}catch(e){reject(e);}}); req.on('error',reject); }); }
function bearer(req) { const h=req.headers.authorization||''; return h.startsWith('Bearer ')?h.slice(7):''; }
function getDevice(req) { const t=bearer(req); for(const d of devices.values()) if(d.token===t) return d; return null; }
function getParent(req) { const t=bearer(req); return parentTokens.get(t)||null; }
function clean() { for(const [c,v] of pairCodes) if(v.expires<now()) pairCodes.delete(c); for(const [t,v] of parentTokens) if(v.expires<now()) parentTokens.delete(t); for(const d of devices.values()) if(d.request && d.request.expires<now()) d.request=null; }
const server=http.createServer(async(req,res)=>{
  res.setHeader('access-control-allow-origin','*'); res.setHeader('access-control-allow-headers','content-type,authorization'); res.setHeader('access-control-allow-methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
  try {
    clean(); const u=new URL(req.url,'http://localhost');
    if(req.method==='GET'&&u.pathname==='/health') return send(res,200,{ok:true,service:'ParentGuard relay'});
    if(req.method==='POST'&&u.pathname==='/v1/pair/start'){
      const b=await read(req); const deviceId=crypto.randomUUID(); const deviceToken=token(); const pairingCode=code();
      devices.set(deviceId,{id:deviceId,token:deviceToken,created:now(),lastSeen:0,snapshot:{status:'Waiting for first sync'},frame:null,request:null,sharing:false,messages:[],commands:[],timeRequest:null});
      pairCodes.set(pairingCode,{deviceId,expires:now()+5*60*1000});
      return send(res,200,{deviceId,deviceToken,pairingCode,expiresInSeconds:300});
    }
    if(req.method==='POST'&&u.pathname==='/v1/pair/claim'){
      const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
      const attempts=claimAttempts.get(ip)||{count:0,start:now()}; if(now()-attempts.start>5*60*1000){attempts.count=0;attempts.start=now();} attempts.count++; claimAttempts.set(ip,attempts);
      if(attempts.count>12)return send(res,429,{error:'Too many pairing attempts. Wait five minutes.'});
      const b=await read(req); const p=pairCodes.get(String(b.code||'')); if(!p||p.expires<now()) return send(res,401,{error:'Pairing code invalid or expired'});
      pairCodes.delete(String(b.code)); const parentToken=token(); parentTokens.set(parentToken,{deviceId:p.deviceId,expires:now()+30*24*60*60*1000});
      return send(res,200,{deviceId:p.deviceId,parentToken,expiresInSeconds:30*24*60*60});
    }
    if(req.method==='POST'&&u.pathname==='/v1/snapshot'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req);
      d.snapshot={...b,receivedAt:now()}; d.lastSeen=now(); return send(res,200,{ok:true,request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='GET'&&u.pathname==='/v1/snapshot'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      return send(res,200,{deviceId:d.id,online:now()-d.lastSeen<60000,lastSeen:d.lastSeen,snapshot:d.snapshot,sharing:d.sharing,request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='POST'&&u.pathname==='/v1/control'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const b=await read(req); const type=String(b.type||''); if(!['lock','unlock','setLimit','grantTime'].includes(type))return send(res,400,{error:'Invalid control type'});
      const minutes=(type==='setLimit' && Number(b.minutes)===0)?0:Math.max(1,Math.min(720,Math.floor(Number(b.minutes)||15)));
      if(type==='setLimit' && (!Number.isFinite(Number(b.minutes)) || Number(b.minutes)<0 || Number(b.minutes)>720))return send(res,400,{error:'Limit must be between 0 and 720 minutes'});
      const cmd={id:token(),type,minutes,created:now()}; d.commands=d.commands||[]; d.commands.push(cmd); if(d.commands.length>20)d.commands=d.commands.slice(-20); return send(res,200,{ok:true,commandId:cmd.id});
    }
    if(req.method==='GET'&&u.pathname==='/v1/control'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); return send(res,200,{commands:(d.commands||[]).slice(0,10)});
    }
    if(req.method==='POST'&&u.pathname==='/v1/control/ack'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); d.commands=(d.commands||[]).filter(x=>x.id!==String(b.id||'')); return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&u.pathname==='/v1/time-request'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); const minutes=Math.max(5,Math.min(120,Math.floor(Number(b.minutes)||15)));
      d.timeRequest={id:token(),minutes,created:now(),status:'pending'}; return send(res,200,{ok:true,id:d.timeRequest.id});
    }
    if(req.method==='GET'&&u.pathname==='/v1/time-request'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'}); return send(res,200,{request:d.timeRequest});
    }
    if(req.method==='POST'&&u.pathname==='/v1/time-request/respond'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'}); const b=await read(req); if(!d.timeRequest||d.timeRequest.id!==String(b.id||''))return send(res,409,{error:'Time request expired or already handled'});
      const reqMinutes=d.timeRequest.minutes; const approve=!!b.approve; d.timeRequest={...d.timeRequest,status:approve?'approved':'declined',handledAt:now()}; if(approve){d.commands=d.commands||[];d.commands.push({id:token(),type:'grantTime',minutes:Math.max(1,Math.min(120,Math.floor(Number(b.minutes)||reqMinutes))),created:now()});} return send(res,200,{ok:true,status:d.timeRequest.status});
    }
    if(req.method==='POST'&&u.pathname==='/v1/message'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const b=await read(req); const message=String(b.message||'').trim(); if(!message)return send(res,400,{error:'Message cannot be empty'}); if(message.length>500)return send(res,413,{error:'Message must be 500 characters or fewer'});
      const item={id:token(),text:message,created:now()}; d.messages=d.messages||[]; d.messages.push(item); if(d.messages.length>20)d.messages=d.messages.slice(-20);
      return send(res,200,{ok:true,messageId:item.id});
    }
    if(req.method==='GET'&&u.pathname==='/v1/message'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const item=(d.messages||[])[0]||null; return send(res,200,{message:item});
    }
    if(req.method==='POST'&&u.pathname==='/v1/message/ack'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); d.messages=(d.messages||[]).filter(m=>m.id!==String(b.id||'')); return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/request'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      d.request={id:token(),created:now(),expires:now()+2*60*1000}; return send(res,200,{ok:true,expiresInSeconds:120});
    }
    if(req.method==='GET'&&u.pathname==='/v1/screen/request'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); return send(res,200,{request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/state'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); d.sharing=!!b.sharing; if(!d.sharing)d.frame=null; if(b.requestId&&d.request&&d.request.id===b.requestId)d.request=null; return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/frame'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); if(!d.sharing)return send(res,403,{error:'No approved screen session'});
      const raw=String(b.jpegBase64||''); if(raw.length>1500000)return send(res,413,{error:'Frame too large'}); if(!/^[A-Za-z0-9+/]*={0,2}$/.test(raw))return send(res,400,{error:'Invalid frame'});
      d.frame={jpegBase64:raw,at:now()}; d.lastSeen=now(); return send(res,200,{ok:true});
    }
    if(req.method==='GET'&&u.pathname==='/v1/screen/frame'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'}); return send(res,200,{sharing:d.sharing,frame:d.frame});
    }
    return send(res,404,{error:'Not found'});
  } catch(e) { return send(res,400,{error:'Bad request'}); }
});
server.listen(PORT,'0.0.0.0',()=>console.log('ParentGuard relay listening on '+PORT+' (deploy behind HTTPS/TLS proxy)'));
