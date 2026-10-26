/* JWT Inspector — decoding is plain Base64URL + JSON.parse; HMAC verify uses crypto.subtle. */
(function () {
  "use strict";
  var $ = S3.$;
  var HS = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };
  var CLAIMS = {
    iss: "Issuer", sub: "Subject", aud: "Audience", jti: "Token ID", azp: "Authorized party", scope: "Scope",
    nonce: "Nonce", sid: "Session ID", email: "Email", name: "Name", roles: "Roles", typ: "Type"
  };
  var TIMES = [["iat", "Issued at"], ["nbf", "Not before"], ["exp", "Expires"], ["auth_time", "Authenticated at"]];

  // ---------- core ----------
  function b64urlToBytes(s) {
    if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) throw new Error("not Base64URL");
    s = s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
    if (s.length % 4 === 1) throw new Error("bad Base64URL length");
    var bin = atob(s + "===".slice(0, (4 - s.length % 4) % 4)), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64url(b) {
    var s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function partJSON(seg, label) {
    var txt;
    try { txt = new TextDecoder("utf-8", { fatal: true }).decode(b64urlToBytes(seg)); }
    catch (e) { throw new Error(label + " is not valid Base64URL"); }
    try { return JSON.parse(txt); } catch (e) { throw new Error(label + " is not valid JSON"); }
  }
  function decode(token) {
    var t = String(token).trim().replace(/^Bearer\s+/i, "").replace(/\s+/g, "");
    var parts = t.split(".");
    if (parts.length === 5) throw new Error("This is an encrypted JWE (5 parts). Its payload can only be read with the decryption key");
    if (parts.length !== 3) throw new Error("A JWT has 3 parts separated by dots — found " + parts.length);
    return { raw: t, parts: parts, header: partJSON(parts[0], "Header"), payload: partJSON(parts[1], "Payload") };
  }
  function keyBytes(secret, isB64) {
    if (!isB64) return new TextEncoder().encode(secret);
    return b64urlToBytes(secret.trim().replace(/\+/g, "-").replace(/\//g, "_"));
  }
  function hsSign(alg, key, data) {
    return crypto.subtle.importKey("raw", key, { name: "HMAC", hash: HS[alg] }, false, ["sign"])
      .then(function (k) { return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(data)); })
      .then(function (s) { return bytesToB64url(new Uint8Array(s)); });
  }
  function verify(dec, secret, isB64) {
    var alg = dec.header.alg;
    if (!HS[alg]) return Promise.resolve(null);
    return hsSign(alg, keyBytes(secret, isB64), dec.parts[0] + "." + dec.parts[1]).then(function (sig) { return sig === dec.parts[2]; });
  }
  function rel(sec, nowSec) {
    var d = sec - nowSec, a = Math.abs(d);
    var U = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    for (var i = 0; i < U.length; i++) if (a >= U[i][1] || i === U.length - 1) {
      return new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(Math.round(d / U[i][1]), U[i][0]);
    }
  }
  // → {cls, text}. Times are seconds since epoch (RFC 7519 NumericDate).
  function validity(p, nowSec) {
    if (typeof p.exp === "number" && p.exp <= nowSec) return { cls: "bad", text: "Expired " + rel(p.exp, nowSec) };
    if (typeof p.nbf === "number" && p.nbf > nowSec) return { cls: "warn", text: "Not valid yet — starts " + rel(p.nbf, nowSec) };
    if (typeof p.exp === "number") return { cls: "ok", text: "Valid · expires " + rel(p.exp, nowSec) };
    return { cls: "warn", text: "No expiry (exp) claim" };
  }

  // ---------- UI ----------
  var tokenEl = $("#token"), state = { dec: null, verifyToken: 0 };

  function chip(el, cls, text) { el.className = "chip " + (cls || ""); el.textContent = text; el.hidden = false; }
  function row(tbody, k, v, sub) {
    tbody.appendChild(S3.h("tr", null, [S3.h("th", { text: k }), S3.h("td", null, [S3.h("span", { "class": "mono", text: v }), sub ? S3.h("div", { "class": "faint", text: sub }) : null])]));
  }
  function reset(msg, cls) {
    state.dec = null;
    chip($("#status"), cls, msg); $("#algChip").hidden = true;
    $("#header").textContent = ""; $("#payload").textContent = "";
    $("#times tbody").innerHTML = ""; $("#claimsWrap").hidden = true;
    $("#times tbody").appendChild(S3.h("tr", null, [S3.h("td", { "class": "faint", text: "Paste a token to see when it was issued and when it expires." })]));
    chip($("#expChip"), "", "—"); chip($("#sigStatus"), "", "Enter the secret to verify");
  }

  function render() {
    var v = tokenEl.value;
    if (!v.trim()) { reset("Waiting for a token"); $("#colored").textContent = ""; return; }
    var parts = v.trim().replace(/^Bearer\s+/i, "").replace(/\s+/g, "").split(".");
    var col = $("#colored"); col.textContent = "";
    ["h", "p", "s", "x", "x"].forEach(function (c, i) {
      if (i >= parts.length) return;
      if (i) col.appendChild(S3.h("span", { "class": "dot", text: "." }));
      col.appendChild(S3.h("span", { "class": c, text: parts[i] }));
    });
    var dec;
    try { dec = decode(v); } catch (e) { reset(e.message, "bad"); return; }
    state.dec = dec;
    chip($("#status"), "ok", "Decoded");
    var alg = String(dec.header.alg || "?");
    chip($("#algChip"), alg.toLowerCase() === "none" ? "bad" : "accent", alg.toLowerCase() === "none" ? "alg: none — unsigned!" : "alg: " + alg);
    $("#header").textContent = JSON.stringify(dec.header, null, 2);
    $("#payload").textContent = JSON.stringify(dec.payload, null, 2);

    var now = Date.now() / 1000, p = dec.payload, tb = $("#times tbody");
    tb.innerHTML = "";
    var any = false;
    TIMES.forEach(function (t) {
      if (!(t[0] in p)) return;
      any = true;
      var n = p[t[0]];
      if (typeof n !== "number") { row(tb, t[1], String(n), "Not a number — should be seconds since 1970"); return; }
      var note = n > 1e11 ? "Looks like milliseconds; JWT times are in seconds" : rel(n, now);
      row(tb, t[1], new Date(n * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" }), t[0] + " = " + n + " · " + note);
    });
    if (!any) tb.appendChild(S3.h("tr", null, [S3.h("td", { "class": "faint", text: "No iat / nbf / exp claims in this token." })]));
    var val = validity(p, now); chip($("#expChip"), val.cls, val.text);

    var cb = $("#claims tbody"); cb.innerHTML = "";
    Object.keys(p).forEach(function (k) {
      if (!CLAIMS[k]) return;
      var x = p[k];
      row(cb, CLAIMS[k] + " (" + k + ")", typeof x === "string" ? x : JSON.stringify(x));
    });
    $("#claimsWrap").hidden = !cb.children.length;
    checkSig();
  }

  function checkSig() {
    var dec = state.dec, sec = $("#secret").value, el = $("#sigStatus"), my = ++state.verifyToken;
    if (!dec) return;
    if (!HS[dec.header.alg]) {
      chip(el, "", String(dec.header.alg).toLowerCase() === "none" ? "No signature to verify" : dec.header.alg + " needs a public key — not verified here");
      return;
    }
    if (!sec) { chip(el, "", "Enter the secret to verify"); return; }
    var p;
    try { p = verify(dec, sec, $("#secretB64").checked); } catch (e) { chip(el, "bad", "Secret is not valid Base64"); return; }
    p.then(function (ok) {
      if (my !== state.verifyToken) return;
      chip(el, ok ? "ok" : "bad", ok ? "✓ Signature verified" : "✗ Invalid signature");
      if (ok) S3.done();
    }, function () { chip(el, "bad", "Could not verify"); });
  }

  tokenEl.addEventListener("input", S3.debounce(render, 120));
  $("#secret").addEventListener("input", S3.debounce(checkSig, 150));
  $("#secretB64").addEventListener("change", checkSig);
  $("#clear").addEventListener("click", function () { tokenEl.value = ""; $("#secret").value = ""; render(); tokenEl.focus(); });
  var SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  $("#sample").addEventListener("click", function () { tokenEl.value = SAMPLE; $("#secret").value = "your-256-bit-secret"; $("#secretB64").checked = false; render(); });
  $("#copyHeader").addEventListener("click", function () { if (state.dec) S3.copy($("#header").textContent, "Header copied"); });
  $("#copyPayload").addEventListener("click", function () { if (state.dec) { S3.copy($("#payload").textContent, "Payload copied"); S3.done(); } });

  function makeToken(header, payload, secret) {
    var enc = function (o) { return bytesToB64url(new TextEncoder().encode(JSON.stringify(o))); };
    var data = enc(header) + "." + enc(payload);
    return hsSign(header.alg, new TextEncoder().encode(secret), data).then(function (s) { return data + "." + s; });
  }

  render();

  window.S3_DEMO = async function () {
    var now = Math.floor(Date.now() / 1000);
    tokenEl.value = await makeToken({ alg: "HS256", typ: "JWT" },
      { iss: "https://s3eidat.github.io", sub: "user_42", name: "Ada Lovelace", aud: "demo-app", roles: ["admin"], iat: now - 3600, nbf: now - 3600, exp: now + 2 * 3600 },
      "demo-secret");
    $("#secret").value = "demo-secret";
    render();
    await new Promise(function (r) { setTimeout(r, 100); });
  };

  window.S3_SELFTEST = async function () {
    var d = decode("Bearer " + SAMPLE);
    if (d.header.alg !== "HS256" || d.payload.name !== "John Doe" || d.payload.iat !== 1516239022) return "decode";
    if (await verify(d, "your-256-bit-secret", false) !== true) return "verify jwt.io sample";
    if (await verify(d, "wrong", false) !== false) return "verify should fail";
    // RFC 7515 A.1: HS256 with a Base64URL key
    var rfc = decode("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    if (await verify(rfc, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", true) !== true) return "rfc7515";
    if (rfc.payload.exp !== 1300819380) return "rfc7515 payload";
    var t = await makeToken({ alg: "HS512" }, { a: "مرحبا" }, "k");
    if (!(await verify(decode(t), "k", false)) || decode(t).payload.a !== "مرحبا") return "hs512 roundtrip";
    if (validity({ exp: 100 }, 200).cls !== "bad" || validity({ nbf: 300, exp: 400 }, 200).cls !== "warn" || validity({ exp: 400 }, 200).cls !== "ok") return "validity";
    if (rel(200 - 3 * 3600, 200) !== "3 hours ago" || rel(200 + 120, 200) !== "in 2 minutes") return "relative";
    try { decode("a.b"); return "2 parts accepted"; } catch (e) { /* expected */ }
    try { decode("a.b.c.d.e"); return "jwe accepted"; } catch (e) { if (!/JWE/.test(e.message)) return "jwe msg"; }
    return true;
  };
})();
