'use strict';
// The reading key stays in this browser; fetches contain only paths to ciphertext.
(()=>{
 const encoder=new TextEncoder(),keyName='mozhou-pages-key';
 let master='';try{master=localStorage.getItem(keyName)||'';}catch{}
 const from64=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const locked=()=>Object.assign(new Error('请使用电脑端的阅读链接或阅读密钥解锁。'),{status:401});
 async function derive(purpose,secret,algorithm,usage){const bytes=await crypto.subtle.digest('SHA-256',encoder.encode('mozhou-v1:'+purpose+':'+secret));return crypto.subtle.importKey('raw',bytes,algorithm,false,usage);}
 async function decrypt(envelope,secret){
  if(envelope.v!==1)throw new Error('不支持此加密版本。');
  const iv=from64(envelope.iv),data=from64(envelope.data),signed=new Uint8Array(iv.length+data.length);signed.set(iv);signed.set(data,iv.length);
  if(iv.length!==16||!await crypto.subtle.verify('HMAC',await derive('mac',secret,{name:'HMAC',hash:'SHA-256'},['verify']),from64(envelope.mac),signed))throw locked();
  const clear=await crypto.subtle.decrypt({name:'AES-CBC',iv},await derive('enc',secret,'AES-CBC',['decrypt']),data);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(clear));
 }
 async function read(file,secret,signal){
  if(!/^data\/(?:parts\/[a-f0-9]{64}|books\/[A-Za-z0-9_-]{8,64}\/[a-f0-9]{64}|index)\.mzr$/.test(file))throw new Error('书库路径无效。');
  const response=await fetch(new URL(file+(file==='data/index.mzr'?'?v='+Date.now():''),document.baseURI),{cache:file==='data/index.mzr'?'no-store':'default',signal});
  if(!response.ok)throw new Error(response.status===404?'书库正在发布，请稍后刷新。':'无法加载云端书库，请检查网络。');
  return decrypt(await response.json(),secret);
 }
 let catalog=null,books=new Map();
 window.MozhouTransport={decrypt,async api(path,options={}){
  if(path==='/api/login'){
   const candidate=JSON.parse(options.body).key.trim();if(!/^[A-Za-z0-9_-]{43}$/.test(candidate))throw locked();
   const loaded=await read('data/index.mzr',candidate);master=candidate;catalog=loaded;books.clear();try{localStorage.setItem(keyName,master);}catch{}return{ok:true};
  }
  if(path==='/api/logout'){master='';catalog=null;books.clear();try{localStorage.removeItem(keyName);}catch{}return{ok:true};}
  if(!master)throw locked();
  if(path==='/api/books'){catalog=await read('data/index.mzr',master,options.signal);return catalog;}
  const match=path.match(/^\/api\/books\/([A-Za-z0-9_-]{8,64})(?:\/parts\/(\d+)(?:\?revision=([a-f0-9]{64}))?)?$/);
  if(!match)throw new Error('未找到这一页。');
  if(!catalog)catalog=await read('data/index.mzr',master,options.signal);
  const summary=catalog.books.find(b=>b.id===match[1]);if(!summary)throw new Error('小说尚未同步，请刷新书架。');
  const identity=summary.id+'|'+summary.revision;let book=books.get(identity);
  if(!book){book=await read(summary.file,master,options.signal);books.clear();books.set(identity,book);}
  if(match[2]===undefined)return book;
  if(match[3]&&match[3]!==book.revision)throw Object.assign(new Error('版本已更新，请重新打开小说。'),{status:409});
  const part=book.parts[Number(match[2])];if(!part)throw new Error('未找到这一节。');return read(part.file,master,options.signal);
 }};
 const fragment=new URLSearchParams(location.hash.slice(1)),incoming=fragment.get('key');
 if(incoming){history.replaceState(null,'',location.pathname+location.search);if(/^[A-Za-z0-9_-]{43}$/.test(incoming)){document.addEventListener('DOMContentLoaded',()=>{const input=document.getElementById('accessKey');input.value=incoming;document.getElementById('loginForm').requestSubmit();},{once:true});}}
})();
