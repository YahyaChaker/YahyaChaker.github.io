/* cloud.js — shared sign-in + per-user document store for The Ledger pages.
   Neon Auth (cookie session) + Neon Data API (PostgREST) over public.user_docs.
   Row-level security: each user reads/writes only their own rows.
   No secrets here — security is enforced server-side by RLS + JWT. */
window.LedgerCloud = (function(){
"use strict";
var AUTH_URL = "https://ep-cold-poetry-axjdfnxy.neonauth.c-4.us-east-2.aws.neon.tech/neondb/auth";
var API_URL  = "https://ep-cold-poetry-axjdfnxy.apirest.c-4.us-east-2.aws.neon.tech/neondb/rest/v1";
var C = { user:null, jwt:null, jwtExp:0 };
var els = {};
var onUserCb = null;

function enc(s){ return encodeURIComponent(s); }

function setStatus(msg, err){
  if(els.status) els.status.textContent = msg;
  if(els.err) els.err.textContent = err || "";
}

function renderBar(){
  var on = !!C.user;
  if(!els.bar) return;
  els.bar.classList.toggle("on", on);
  els.form.style.display = on ? "none" : "contents";
  els.signout.style.display = on ? "" : "none";
  els.who.textContent = on ? C.user.email : "";
}

function authFetch(path, opts){
  opts = opts || {};
  opts.credentials = "include";
  opts.headers = Object.assign({"Content-Type":"application/json"}, opts.headers || {});
  return fetch(AUTH_URL + path, opts).then(function(r){
    return r.json().catch(function(){ return null; }).then(function(data){
      if(!r.ok) throw new Error((data && (data.message || data.error)) || ("HTTP " + r.status));
      return data;
    });
  });
}

function jwt(force){
  var now = Date.now()/1000;
  if(!force && C.jwt && C.jwtExp - now > 60) return Promise.resolve(C.jwt);
  return authFetch("/token").then(function(d){
    var t = d && (d.token || d.jwt);
    if(!t) throw new Error("No token issued");
    C.jwt = t;
    try{
      C.jwtExp = JSON.parse(atob(t.split(".")[1].replace(/-/g,"+").replace(/_/g,"/"))).exp || (now + 300);
    }catch(e){ C.jwtExp = now + 300; }
    return t;
  });
}

/* generic table call */
function api(table, method, qs, body, prefer){
  return jwt().then(function(t){
    var headers = {"Authorization":"Bearer " + t, "Content-Type":"application/json"};
    if(prefer) headers["Prefer"] = prefer;
    return fetch(API_URL + "/" + table + (qs || ""), {
      method: method, headers: headers,
      body: body ? JSON.stringify(body) : undefined
    });
  }).then(function(r){
    if(r.status === 401 || r.status === 403) C.jwt = null;   // force refresh next call
    if(!r.ok) return r.text().then(function(t){ throw new Error(t.slice(0,160) || ("HTTP " + r.status)); });
    return r.text().then(function(t){ return t ? JSON.parse(t) : null; });
  });
}

function needUser(){ if(!C.user) return Promise.reject(new Error("Not signed in")); }

/* ---- user_docs API ---- */
function putDoc(kind, ref, data, pdfB64){
  if(!C.user) return Promise.resolve();           // signed out: local-only, silently skip
  var row = { user_id: C.user.id, kind: kind, ref: String(ref), data: data, updated_at: new Date().toISOString() };
  if(pdfB64 != null) row.pdf = pdfB64;
  return api("user_docs","POST","", [row], "resolution=merge-duplicates,return=minimal");
}
function getDoc(kind, ref, withPdf){
  if(!C.user) return Promise.resolve(null);
  return api("user_docs","GET","?user_id=eq."+enc(C.user.id)+"&kind=eq."+enc(kind)+"&ref=eq."+enc(ref)+"&select=" + (withPdf?"data,pdf":"data"))
    .then(function(rows){ return rows && rows[0] ? rows[0] : null; });
}
function listDocs(kind){
  if(!C.user) return Promise.resolve([]);
  return api("user_docs","GET","?user_id=eq."+enc(C.user.id)+"&kind=eq."+enc(kind)+"&select=ref,data,updated_at&order=ref.desc")
    .then(function(rows){ return rows || []; });
}
function delDoc(kind, ref){
  if(!C.user) return Promise.resolve();
  return api("user_docs","DELETE","?user_id=eq."+enc(C.user.id)+"&kind=eq."+enc(kind)+"&ref=eq."+enc(ref));
}
/* data-only update that never touches the pdf column; falls back to insert */
function patchDoc(kind, ref, data){
  if(!C.user) return Promise.resolve();
  var qs = "?user_id=eq."+enc(C.user.id)+"&kind=eq."+enc(kind)+"&ref=eq."+enc(ref);
  return api("user_docs","PATCH", qs, { data: data, updated_at: new Date().toISOString() }, "return=representation")
    .then(function(rows){
      if(rows && rows.length) return;
      return putDoc(kind, ref, data);
    });
}
function getPdf(kind, ref){
  if(!C.user) return Promise.resolve(null);
  return api("user_docs","GET","?user_id=eq."+enc(C.user.id)+"&kind=eq."+enc(kind)+"&ref=eq."+enc(ref)+"&select=pdf")
    .then(function(rows){ return rows && rows[0] && rows[0].pdf; });
}
function getLedger(){
  if(!C.user) return Promise.resolve(null);
  return api("ledger_state","GET","?user_id=eq."+enc(C.user.id)+"&select=data")
    .then(function(rows){ return rows && rows[0] && rows[0].data; });
}

/* ---- auth ---- */
function afterAuth(u){
  C.user = u; C.jwt = null;
  renderBar();
  if(onUserCb) onUserCb(C.user);
}
function auth(path){
  var email = els.email.value.trim();
  var pass  = els.pass.value;
  if(!email || !pass){ setStatus("Enter email and password"); return; }
  setStatus("Working…");
  var body = (path === "/sign-up/email")
    ? {name: email.split("@")[0], email: email, password: pass}
    : {email: email, password: pass};
  authFetch(path, {method:"POST", body: JSON.stringify(body)})
    .then(function(d){
      if(d && d.user) return d.user;
      return authFetch("/get-session").then(function(s){ return s && s.user; });
    })
    .then(function(u){
      if(!u) throw new Error("Sign-in did not return a session");
      setStatus("Signed in ✓");
      afterAuth(u);
    })
    .catch(function(e){
      var m = String(e.message || e);
      var diag = " [page: " + location.protocol + "//" + location.host +
                 (window.top !== window.self ? ", in-frame" : ", own-tab") + "]";
      if(/failed to fetch|networkerror|load failed|403|forbidden|null origin/i.test(m)){
        m = "Sign-in isn't enabled for this address yet. Send this line: " + location.origin + diag;
      } else { m = m + diag; }
      setStatus("Local only — sign-in failed", m);
    });
}
function signOut(){
  authFetch("/sign-out", {method:"POST", body:"{}"}).catch(function(){});
  C.user = null; C.jwt = null;
  renderBar(); setStatus("Signed out — data stays in this browser");
  if(onUserCb) onUserCb(null);
}

var CSS = [
 ".cloudbar{max-width:1160px;margin:14px auto 0;padding:0 28px;}",
 ".cloudbar-inner{display:flex;align-items:center;gap:14px;flex-wrap:wrap;border:1px solid var(--ink);background:var(--card);padding:9px 16px;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.06em;}",
 ".cloudbar .dot{width:8px;height:8px;border-radius:50%;background:var(--muted);display:inline-block}",
 ".cloudbar.on .dot{background:var(--good)}",
 ".cloudbar .status{color:var(--muted)}",
 ".cloudbar .who{color:var(--ink-deep);font-weight:700}",
 ".cloudbar button{background:none;border:1px solid var(--ink);color:var(--ink-deep);font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;padding:5px 12px;cursor:pointer;}",
 ".cloudbar button:hover{border-color:var(--accent);color:var(--accent)}",
 ".cloudbar button.primary{background:var(--accent);border-color:var(--accent);color:#fff}",
 ".cloudbar button.primary:hover{opacity:.9;color:#fff}",
 ".cloudbar input{background:var(--cream);border:1px solid var(--rule);color:var(--ink-deep);font-family:'JetBrains Mono',monospace;font-size:11.5px;padding:5px 8px;width:180px;outline:none;}",
 ".cloudbar input:focus{border-color:var(--accent)}",
 ".cloudbar .err{color:#a32c00;width:100%}"
].join("\n");

/* mount(hostEl, { onUser: fn(user|null), statusText: "..." }) */
function mount(host, opts){
  opts = opts || {};
  onUserCb = opts.onUser || null;
  var st = document.createElement("style");
  st.textContent = CSS;
  document.head.appendChild(st);

  host.className = (host.className ? host.className + " " : "") + "cloudbar";
  host.innerHTML =
    '<div class="cloudbar-inner">' +
      '<span class="dot"></span>' +
      '<span class="status">' + esc(opts.statusText || "Local only — your data stays in this browser") + '</span>' +
      '<span class="who"></span>' +
      '<span style="flex:1"></span>' +
      '<span class="cl-form" style="display:contents">' +
        '<input class="cl-email" type="email" placeholder="email" autocomplete="email">' +
        '<input class="cl-pass" type="password" placeholder="password" autocomplete="current-password">' +
        '<button class="cl-signin primary">Sign in</button>' +
        '<button class="cl-signup">Sign up</button>' +
      '</span>' +
      '<button class="cl-signout" style="display:none">Sign out</button>' +
      '<span class="err"></span>' +
    '</div>';
  els = {
    bar: host,
    status: host.querySelector(".status"),
    err: host.querySelector(".err"),
    who: host.querySelector(".who"),
    form: host.querySelector(".cl-form"),
    signout: host.querySelector(".cl-signout"),
    email: host.querySelector(".cl-email"),
    pass: host.querySelector(".cl-pass")
  };
  host.querySelector(".cl-signin").onclick = function(){ auth("/sign-in/email"); };
  host.querySelector(".cl-signup").onclick = function(){ auth("/sign-up/email"); };
  els.signout.onclick = signOut;

  /* resume existing session, if any */
  authFetch("/get-session")
    .then(function(s){
      if(s && s.user){ C.user = s.user; setStatus("Signed in ✓"); }
      renderBar();
      if(onUserCb) onUserCb(C.user);
    })
    .catch(function(){ renderBar(); if(onUserCb) onUserCb(null); });
}
function esc(s){ return String(s).replace(/[&<>"]/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]; }); }

return {
  mount: mount,
  user: function(){ return C.user; },
  note: setStatus,
  putDoc: putDoc, getDoc: getDoc, listDocs: listDocs, delDoc: delDoc, patchDoc: patchDoc,
  getPdf: getPdf, getLedger: getLedger
};
})();
