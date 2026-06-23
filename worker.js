export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/favicon.svg') {
      return new Response(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
        '<rect width="64" height="64" rx="14" fill="#000"/>' +
        '<path d="M16 44V20h8v24z" fill="none" stroke="#fff" stroke-width="2"/>' +
        '<rect x="28" y="20" width="20" height="24" rx="3" fill="none" stroke="#fff" stroke-width="2"/>' +
        '<line x1="32" y1="26" x2="44" y2="26" stroke="#fff" stroke-width="1.5" opacity="0.5"/>' +
        '<line x1="32" y1="30" x2="44" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.5"/>' +
        '<line x1="32" y1="34" x2="40" y2="34" stroke="#fff" stroke-width="1.5" opacity="0.5"/>' +
        '<circle cx="38" cy="40" r="2.5" fill="none" stroke="#fff" stroke-width="1.5"/>' +
        '<line x1="40" y1="42" x2="43" y2="45" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>' +
        '</svg>',
        { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } }
      );
    }
    if (request.method === 'POST' && url.pathname === '/api/encode') return handleEncode(request);
    if (request.method === 'POST' && url.pathname === '/api/decode') return handleDecode(request);
    return new Response(getHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};

async function handleEncode(request) {
  try {
    const fd = await request.formData();
    const imageFile = fd.get('image');
    const message = fd.get('message') || '';
    const hiddenFile = fd.get('hiddenFile');
    const password = fd.get('password') || '';
    const lang = fd.get('lang') || 'fa';
    const mode = fd.get('mode') || 'text';
    const t = srvStr(lang);
    if (!imageFile) return jRes({ error: true, message: t[0] }, 400);
    if (mode === 'text' && !message) return jRes({ error: true, message: t[1] }, 400);
    if (mode === 'file' && !hiddenFile) return jRes({ error: true, message: t[2] }, 400);
    if (imageFile.size > 15 * 1024 * 1024) return jRes({ error: true, message: t[3] }, 400);
    let ib = new Uint8Array(await imageFile.arrayBuffer());
    if (!isPNG(ib) && !isJPG(ib)) return jRes({ error: true, message: t[4] }, 400);
    if (isJPG(ib)) {
      ib = await jpg2png(ib);
      if (!ib) return jRes({ error: true, message: t[5] }, 500);
    }
    let raw, pt = 0;
    if (mode === 'file') {
      const fb = new Uint8Array(await hiddenFile.arrayBuffer());
      const fnb = new TextEncoder().encode(hiddenFile.name || 'file');
      raw = new Uint8Array(2 + fnb.length + fb.length);
      raw[0] = (fnb.length >> 8) & 0xFF; raw[1] = fnb.length & 0xFF;
      raw.set(fnb, 2); raw.set(fb, 2 + fnb.length); pt = 2;
    } else { raw = new TextEncoder().encode(message); pt = 1; }
    let data, enc = false;
    if (password) { data = await aesEnc(raw, password); enc = true; } else data = raw;
    const flags = (enc ? 1 : 0) | (pt << 1);
    const pl = new Uint8Array(1 + 4 + data.length + 8);
    pl[0] = flags;
    pl[1] = (data.length >> 24) & 0xFF; pl[2] = (data.length >> 16) & 0xFF;
    pl[3] = (data.length >> 8) & 0xFF; pl[4] = data.length & 0xFF;
    pl.set(data, 5);
    pl.set(new Uint8Array(await sha8(data)), 5 + data.length);
    const out = embedPNG(ib, pl);
    if (!out) return jRes({ error: true, message: t[6] }, 400);
    return new Response(out, {
      headers: { 'Content-Type': 'image/png', 'Content-Disposition': 'attachment; filename="maskoot_encoded.png"', 'Cache-Control': 'no-store' }
    });
  } catch (e) { return jRes({ error: true, message: srvStr('fa')[7] }, 500); }
}

async function handleDecode(request) {
  try {
    const fd = await request.formData();
    const imageFile = fd.get('image');
    const password = fd.get('password') || '';
    const lang = fd.get('lang') || 'fa';
    const t = srvStr(lang);
    if (!imageFile) return jRes({ error: true, message: t[0] }, 400);
    const ib = new Uint8Array(await imageFile.arrayBuffer());
    if (!isPNG(ib)) return jRes({ error: true, message: t[8] }, 400);
    const pl = extractPNG(ib);
    if (!pl) return jRes({ error: true, message: t[9] }, 404);
    const flags = pl[0], enc = (flags & 1) === 1, pt = (flags >> 1) & 3;
    const len = (pl[1] << 24) | (pl[2] << 16) | (pl[3] << 8) | pl[4];
    if (len <= 0 || len > pl.length - 13) return jRes({ error: true, message: t[10] }, 404);
    const db = pl.slice(5, 5 + len);
    const sc = pl.slice(5 + len, 5 + len + 8);
    const cc = new Uint8Array(await sha8(db));
    let ok = true;
    for (let i = 0; i < 8; i++) if (sc[i] !== cc[i]) { ok = false; break; }
    if (!ok) return jRes({ error: true, message: t[11] }, 404);
    let raw;
    if (enc) {
      if (!password) return jRes({ error: true, message: t[12], encrypted: true }, 403);
      try { raw = await aesDec(db, password); }
      catch { return jRes({ error: true, message: t[13], encrypted: true }, 403); }
    } else raw = db;
    if (pt === 2) {
      const fnl = (raw[0] << 8) | raw[1];
      return jRes({ error: false, type: 'file', fileName: new TextDecoder().decode(raw.slice(2, 2 + fnl)), fileData: u8b64(raw.slice(2 + fnl)), encrypted: enc });
    }
    return jRes({ error: false, type: 'text', message: new TextDecoder().decode(raw), encrypted: enc });
  } catch (e) { return jRes({ error: true, message: srvStr('fa')[14] }, 500); }
}

function srvStr(l) {
  if (l === 'en') return [
    'Please select an image.', 'Please enter a secret message.', 'Please select a file to hide.',
    'Image too large. Max 15MB.', 'Only PNG and JPG are supported.', 'Failed to convert JPG to PNG.',
    'Failed to embed data.', 'Encoding failed.', 'Only PNG is supported for extraction.',
    'No hidden content found.', 'No valid content found.', 'Data corrupted or no content found.',
    'Content is encrypted. Enter password.', 'Wrong password or corrupted data.', 'Decoding failed.'
  ];
  return [
    'لطفاً یک تصویر انتخاب کنید.', 'لطفاً متن محرمانه را وارد کنید.', 'لطفاً فایل مورد نظر را انتخاب کنید.',
    'حجم تصویر بیش از حد مجاز است. حداکثر ۱۵ مگابایت.', 'فقط فرمت‌های PNG و JPG پشتیبانی می‌شوند.',
    'خطا در تبدیل JPG به PNG.', 'خطا در جاسازی داده در تصویر.', 'خطا در پنهان‌سازی.',
    'برای استخراج فقط فرمت PNG پشتیبانی می‌شود.', 'هیچ محتوای پنهانی یافت نشد.',
    'هیچ محتوای معتبری یافت نشد.', 'داده‌ها آسیب دیده یا محتوایی یافت نشد.',
    'محتوا رمزنگاری شده. لطفاً رمز عبور وارد کنید.', 'رمز عبور اشتباه یا داده آسیب دیده.',
    'خطا در استخراج.'
  ];
}

function jRes(d, s = 200) {
  return new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

function isPNG(b) { return b.length > 8 && b[0] === 137 && b[1] === 80 && b[2] === 78 && b[3] === 71; }
function isJPG(b) { return b.length > 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF; }

async function jpg2png(j) {
  const bmp = await createImageBitmap(new Blob([j], { type: 'image/jpeg' }));
  const c = new OffscreenCanvas(bmp.width, bmp.height);
  c.getContext('2d').drawImage(bmp, 0, 0);
  return new Uint8Array(await (await c.convertToBlob({ type: 'image/png' })).arrayBuffer());
}

function embedPNG(p, pl) {
  const ob = xorPl(pl), ct = new TextEncoder().encode('mSKt');
  const cd = new Uint8Array(12 + ob.length);
  cd[0] = (ob.length >> 24) & 0xFF; cd[1] = (ob.length >> 16) & 0xFF;
  cd[2] = (ob.length >> 8) & 0xFF; cd[3] = ob.length & 0xFF;
  cd.set(ct, 4); cd.set(ob, 8);
  const c = crc32(cd.slice(4, 8 + ob.length));
  cd[8 + ob.length] = (c >> 24) & 0xFF; cd[8 + ob.length + 1] = (c >> 16) & 0xFF;
  cd[8 + ob.length + 2] = (c >> 8) & 0xFF; cd[8 + ob.length + 3] = c & 0xFF;
  const cl = rmChunk(p, 'mSKt'), ie = findChunk(cl, 'IEND');
  if (ie === -1) return null;
  const r = new Uint8Array(cl.length + cd.length);
  r.set(cl.slice(0, ie)); r.set(cd, ie); r.set(cl.slice(ie), ie + cd.length);
  return r;
}

function extractPNG(p) {
  const pos = findChunk(p, 'mSKt');
  if (pos === -1) return null;
  const l = (p[pos] << 24) | (p[pos + 1] << 16) | (p[pos + 2] << 8) | p[pos + 3];
  return xorPl(p.slice(pos + 8, pos + 8 + l));
}

function findChunk(p, n) {
  const nb = new TextEncoder().encode(n);
  let o = 8;
  while (o < p.length - 8) {
    const l = (p[o] << 24) | (p[o + 1] << 16) | (p[o + 2] << 8) | p[o + 3];
    let m = true;
    for (let i = 0; i < 4; i++) if (p[o + 4 + i] !== nb[i]) { m = false; break; }
    if (m) return o;
    o += 12 + l;
  }
  return -1;
}

function rmChunk(p, n) {
  const pos = findChunk(p, n);
  if (pos === -1) return p;
  const l = (p[pos] << 24) | (p[pos + 1] << 16) | (p[pos + 2] << 8) | p[pos + 3];
  const r = new Uint8Array(p.length - 12 - l);
  r.set(p.slice(0, pos)); r.set(p.slice(pos + 12 + l), pos);
  return rmChunk(r, n);
}

function xorPl(d) {
  const k = [0x4D, 0x53, 0x4B, 0x54], r = new Uint8Array(d.length);
  for (let i = 0; i < d.length; i++) r[i] = d[i] ^ k[i & 3] ^ (i & 0xFF);
  return r;
}

function crc32(d) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < d.length; i++) { c ^= d[i]; for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (c & 1 ? 0xEDB88320 : 0); }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

async function aesEnc(d, pw) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const s = crypto.getRandomValues(new Uint8Array(16));
  const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: s, iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const e = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, d);
  const r = new Uint8Array(28 + e.byteLength);
  r.set(s); r.set(iv, 16); r.set(new Uint8Array(e), 28);
  return r;
}

async function aesDec(d, pw) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: d.slice(0, 16), iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: d.slice(16, 28) }, k, d.slice(28)));
}

async function sha8(d) { return new Uint8Array(await crypto.subtle.digest('SHA-256', d)).slice(0, 8); }

function u8b64(u) {
  let b = '';
  for (let i = 0; i < u.length; i += 8192) { const c = u.slice(i, i + 8192); for (let j = 0; j < c.length; j++) b += String.fromCharCode(c[j]); }
  return btoa(b);
}
function getHTML() {
  const LG = '<svg class="logo" viewBox="0 0 64 64" fill="none">'
    + '<rect width="64" height="64" rx="14" fill="currentColor"/>'
    + '<path d="M16 44V20h8v24z" fill="none" stroke="var(--logo-s)" stroke-width="2"/>'
    + '<rect x="28" y="20" width="20" height="24" rx="3" fill="none" stroke="var(--logo-s)" stroke-width="2"/>'
    + '<line x1="32" y1="26" x2="44" y2="26" stroke="var(--logo-s)" stroke-width="1.5" opacity="0.5"/>'
    + '<line x1="32" y1="30" x2="44" y2="30" stroke="var(--logo-s)" stroke-width="1.5" opacity="0.5"/>'
    + '<line x1="32" y1="34" x2="40" y2="34" stroke="var(--logo-s)" stroke-width="1.5" opacity="0.5"/>'
    + '<circle cx="38" cy="40" r="2.5" fill="none" stroke="var(--logo-s)" stroke-width="1.5"/>'
    + '<line x1="40" y1="42" x2="43" y2="45" stroke="var(--logo-s)" stroke-width="1.5" stroke-linecap="round"/>'
    + '</svg>';
  const S = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  const SR = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>';
  const LK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>';
  const EY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const CK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';
  const XX = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
  const IM = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>';
  const FL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
  const GH = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>';
  const ST = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';
  const SN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  const MN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  return '<!DOCTYPE html>'
+'<html lang="fa" dir="rtl">'
+'<head>'
+'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">'
+'<title>Maskoot</title>'
+'<meta name="description" content="Maskoot - Free steganography tool. Hide text and files in PNG images with AES-256.">'
+'<meta name="keywords" content="steganography,hide text in image,hide file in image,Maskoot,AES-256">'
+'<meta name="author" content="radmehr2025"><meta name="robots" content="index,follow">'
+'<meta name="theme-color" content="#000"><meta property="og:type" content="website">'
+'<meta property="og:title" content="Maskoot"><meta property="og:description" content="Hide text and files in images.">'
+'<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
+'<style>'
+"@font-face{font-family:'V';src:url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Regular.woff2') format('woff2');font-weight:400;font-display:swap}"
+"@font-face{font-family:'V';src:url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Bold.woff2') format('woff2');font-weight:700;font-display:swap}"
+"@font-face{font-family:'V';src:url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfonts/Vazirmatn-Light.woff2') format('woff2');font-weight:300;font-display:swap}"
+':root{'
+'--bg:#FAFAFA;--fg:#111;--card:rgba(255,255,255,0.92);--border:#E0E0E0;--accent:#000;--ah:#333;'
+'--muted:#777;--ibg:#F5F5F5;--ok:#2E7D32;--err:#C62828;'
+'--sh:0 1px 3px rgba(0,0,0,.08);--shl:0 8px 30px rgba(0,0,0,.08);'
+'--r:12px;--rs:8px;--t:.2s ease;--logo-s:#fff;--geo:rgba(0,0,0,0.04);--geo-line:rgba(0,0,0,0.025)'
+'}'
+'[data-theme=dark]{'
+'--bg:#111;--fg:#EEE;--card:rgba(30,30,30,0.92);--border:#333;--accent:#FFF;--ah:#CCC;'
+'--muted:#999;--ibg:#1A1A1A;--ok:#66BB6A;--err:#EF5350;'
+'--sh:0 1px 3px rgba(0,0,0,.3);--shl:0 8px 30px rgba(0,0,0,.3);'
+'--logo-s:#000;--geo:rgba(255,255,255,0.03);--geo-line:rgba(255,255,255,0.02)'
+'}'
+"*{margin:0;padding:0;box-sizing:border-box}body{font-family:'V',sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;line-height:1.7;overflow-x:hidden;transition:background .3s,color .3s}"
+'html[dir=ltr] body{direction:ltr}'
+'.gbg{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0}.gbg canvas{width:100%;height:100%}'
+'.pc{position:relative;z-index:1}.ct{max-width:1200px;margin:0 auto;padding:0 24px}'
+'header{padding:32px 0 0;text-align:center}.logo{width:48px;height:48px;margin-bottom:12px;color:var(--accent)}'
+'h1{font-size:2.4rem;font-weight:700;letter-spacing:-.5px;color:var(--accent)}.slo{font-size:.95rem;color:var(--muted);margin-top:4px;font-weight:300}'
+'.tbar{position:fixed;top:20px;left:20px;z-index:100;display:flex;gap:8px}'
+'html[dir=ltr] .tbar{left:auto;right:20px}'
+'.tgrp{display:flex;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--card);box-shadow:var(--sh)}'
+".tbtn{padding:8px 14px;border:none;background:transparent;cursor:pointer;font-family:'V',sans-serif;font-size:.85rem;color:var(--muted);transition:all var(--t);display:flex;align-items:center;gap:4px}"
+'.tbtn.act{background:var(--accent);color:var(--bg)}.tbtn:hover:not(.act){background:var(--ibg)}'
+'.tbtn svg{width:16px;height:16px}'
+'.tabs{display:flex;justify-content:center;margin:32px auto 0;max-width:360px;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--card);box-shadow:var(--sh)}'
+".tab{flex:1;padding:12px 24px;border:none;background:transparent;cursor:pointer;font-family:'V',sans-serif;font-size:.95rem;color:var(--muted);transition:all var(--t)}.tab.act{background:var(--accent);color:var(--bg);font-weight:700}.tab:hover:not(.act){background:var(--ibg)}"
+'.ml{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin:40px 0;align-items:start}'
+'.ip{order:2}html[dir=ltr] .ip{order:1}.ap{order:1}html[dir=ltr] .ap{order:2}'
+'.cd{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:32px;box-shadow:var(--shl);backdrop-filter:blur(8px);transition:background .3s,border-color .3s}'
+'.ip .cd{position:sticky;top:24px}'
+'.it{font-size:1.15rem;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}.it svg{width:20px;height:20px}'
+'.ix{font-size:.9rem;color:var(--muted);line-height:2;margin-bottom:12px}.ix:last-of-type{margin-bottom:0}'
+'.sb{margin-top:20px;padding:16px;background:var(--ibg);border-radius:var(--rs);display:flex;align-items:flex-start;gap:12px}.sb svg{width:24px;height:24px;flex-shrink:0;margin-top:2px}.sb p{font-size:.82rem;color:var(--muted);line-height:1.8}'
+'.fg{margin-bottom:20px}.fl{display:block;font-size:.9rem;font-weight:700;margin-bottom:8px}'
+".fi,.ft{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:var(--rs);background:var(--ibg);font-family:'V',sans-serif;font-size:.9rem;color:var(--fg);transition:border-color var(--t);outline:none}.fi:focus,.ft:focus{border-color:var(--accent)}.ft{resize:vertical;min-height:120px}"
+'.pi{text-align:center!important;font-size:1.1rem!important;letter-spacing:4px;font-weight:700}'
+'.ph{font-size:.78rem;color:var(--muted);margin-top:6px;text-align:center}'
+'.fu{border:2px dashed var(--border);border-radius:var(--r);padding:36px 20px;text-align:center;cursor:pointer;transition:all var(--t);position:relative;background:var(--ibg)}'
+'.fu:hover{border-color:var(--accent)}.fu.dg{border-color:var(--accent)}.fu.hf{border-color:var(--accent);border-style:solid}'
+'.fu input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}.fu svg{width:36px;height:36px;margin-bottom:10px;color:var(--muted)}.fu p{font-size:.88rem;color:var(--muted)}'
+'.fn{font-weight:700;color:var(--accent);margin-top:8px;font-size:.85rem;word-break:break-all}.ff{font-size:.75rem;color:var(--muted);margin-top:4px}'
+'.tp{margin-top:12px;max-width:120px;max-height:80px;border-radius:6px;border:1px solid var(--border)}'
+".ms{display:flex;margin-bottom:20px;border:1px solid var(--border);border-radius:8px;overflow:hidden}.mb{flex:1;padding:10px 16px;border:none;background:transparent;cursor:pointer;font-family:'V',sans-serif;font-size:.85rem;color:var(--muted);transition:all var(--t);display:flex;align-items:center;justify-content:center;gap:6px}.mb.act{background:var(--accent);color:var(--bg);font-weight:700}.mb:hover:not(.act){background:var(--ibg)}.mb svg{width:16px;height:16px}"
+".bp{width:100%;padding:14px 24px;background:var(--accent);color:var(--bg);border:none;border-radius:var(--rs);font-family:'V',sans-serif;font-size:1rem;font-weight:700;cursor:pointer;transition:all var(--t);display:flex;align-items:center;justify-content:center;gap:8px}"
+'.bp:hover{background:var(--ah);transform:translateY(-1px)}.bp:active{transform:translateY(0)}.bp:disabled{opacity:.5;cursor:not-allowed;transform:none}'
+'.bp .sp{width:18px;height:18px;border:2px solid rgba(128,128,128,.3);border-top-color:var(--bg);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}'
+'@keyframes spin{to{transform:rotate(360deg)}}'
+'.ra{margin-top:24px;display:none}.ra.v{display:block;animation:fi .3s ease}'
+'@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}'
+'.rs{padding:20px;background:rgba(46,125,50,.1);border:1px solid rgba(46,125,50,.3);border-radius:var(--rs)}.rs .rh{display:flex;align-items:center;gap:8px;font-weight:700;color:var(--ok);margin-bottom:10px}.rs .rh svg{width:20px;height:20px}'
+'.re{padding:20px;background:rgba(198,40,40,.1);border:1px solid rgba(198,40,40,.3);border-radius:var(--rs)}.re .rh{display:flex;align-items:center;gap:8px;font-weight:700;color:var(--err);margin-bottom:6px}.re .rh svg{width:20px;height:20px}'
+'.rm{font-size:.9rem;line-height:2;color:var(--fg);white-space:pre-wrap;word-break:break-word;padding:12px;background:var(--ibg);border-radius:6px;margin-top:8px}'
+'.rac{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}'
+".bs{padding:8px 20px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-family:'V',sans-serif;font-size:.85rem;font-weight:700;transition:all var(--t);text-decoration:none;display:inline-flex;align-items:center}.bs:hover{background:var(--ah)}"
+'.hd{display:none}'
+'footer{text-align:center;padding:32px 0;border-top:1px solid var(--border);margin-top:40px}footer p{font-size:.8rem;color:var(--muted);line-height:2.2}'
+'footer a{color:var(--accent);text-decoration:none;font-weight:700;transition:opacity var(--t)}footer a:hover{opacity:.7}'
+'.fds{margin-top:4px;font-size:.78rem;color:var(--muted);display:flex;align-items:center;justify-content:center;gap:6px}.fds svg{width:16px;height:16px}'
+'.fds:last-child svg{color:#E6A817}'
+'.tc{display:none}.tc.ac{display:block}'
+'@media(max-width:768px){.ml{grid-template-columns:1fr;gap:24px}.ip{order:2!important}.ap{order:1!important}.ip .cd{position:static}h1{font-size:1.8rem}.cd{padding:24px}.tbar{top:12px;left:12px;flex-direction:column}html[dir=ltr] .tbar{left:auto;right:12px}}'
+'</style></head>'
+'<body><div class="gbg"><canvas id="gc"></canvas></div><div class="pc">'

+'<div class="tbar">'
+'<div class="tgrp">'
+'<button class="tbtn act" data-lang="fa" onclick="setLang(\'fa\')">فارسی</button>'
+'<button class="tbtn" data-lang="en" onclick="setLang(\'en\')">English</button>'
+'</div>'
+'<div class="tgrp">'
+'<button class="tbtn act" data-theme="light" onclick="setTheme(\'light\')">' + SN + '</button>'
+'<button class="tbtn" data-theme="dark" onclick="setTheme(\'dark\')">' + MN + '</button>'
+'</div>'
+'</div>'

+'<div class="ct"><header><div>' + LG + '</div>'
+'<h1 data-i18n="title"></h1><p class="slo" data-i18n="slogan"></p></header>'

+'<div class="tabs">'
+'<button class="tab act" data-tab="encode" onclick="sTab(\'encode\')"><span data-i18n="tab_encode"></span></button>'
+'<button class="tab" data-tab="decode" onclick="sTab(\'decode\')"><span data-i18n="tab_decode"></span></button></div>'

+'<div class="tc ac" id="tab-encode"><div class="ml">'
+'<div class="ap"><div class="cd"><form id="ef" onsubmit="doEnc(event)">'
+'<div class="fg"><label class="fl" data-i18n="lb_img"></label>'
+'<div class="fu" id="eu">' + IM + '<p data-i18n="up_hint"></p><p class="ff" data-i18n="up_fmt"></p>'
+'<div class="fn" id="efn" style="display:none"></div><img class="tp" id="eth" style="display:none" alt=""/>'
+'<input type="file" accept="image/png,image/jpeg,image/jpg" id="ei" onchange="hfs(this,\'e\')"/></div></div>'

+'<div class="ms">'
+'<button type="button" class="mb act" data-mode="text" onclick="sMode(\'text\')">' + IM + ' <span data-i18n="m_text"></span></button>'
+'<button type="button" class="mb" data-mode="file" onclick="sMode(\'file\')">' + FL + ' <span data-i18n="m_file"></span></button></div>'

+'<div class="fg" id="tig"><label class="fl" data-i18n="lb_msg"></label>'
+'<textarea class="ft" id="em" placeholder="" data-i18n-ph="ph_msg" maxlength="50000"></textarea></div>'

+'<div class="fg hd" id="fig"><label class="fl" data-i18n="lb_hf"></label>'
+'<div class="fu" id="hfu">' + FL + '<p data-i18n="up_fhint"></p><p class="ff" data-i18n="up_ffmt"></p>'
+'<div class="fn" id="hfn" style="display:none"></div>'
+'<input type="file" id="ehf" onchange="hhfs(this)"/></div></div>'

+'<div class="fg"><label class="fl"><span data-i18n="lb_pw"></span> <span style="font-weight:300;font-size:.8rem" data-i18n="pw_opt"></span></label>'
+'<input type="password" class="fi pi" id="ep" placeholder="••••••••" autocomplete="new-password"/>'
+'<p class="ph" data-i18n="pw_hint"></p></div>'

+'<button type="submit" class="bp" id="eb"><span data-i18n="btn_enc"></span></button>'
+'</form><div class="ra" id="er"></div></div></div>'

+'<div class="ip"><div class="cd">'
+'<h3 class="it">' + S + ' <span data-i18n="it_enc"></span></h3>'
+'<p class="ix" data-i18n="ie1"></p><p class="ix" data-i18n="ie2"></p>'
+'<p class="ix" data-i18n="ie3"></p><p class="ix" data-i18n="ie4"></p>'
+'<div class="sb">' + LK + '<p data-i18n="se"></p></div>'
+'</div></div></div></div>'

+'<div class="tc" id="tab-decode"><div class="ml">'
+'<div class="ap"><div class="cd"><form id="df" onsubmit="doDec(event)">'
+'<div class="fg"><label class="fl" data-i18n="lb_imgd"></label>'
+'<div class="fu" id="du">' + IM + '<p data-i18n="up_hintd"></p><p class="ff" data-i18n="up_fmtd"></p>'
+'<div class="fn" id="dfn" style="display:none"></div><img class="tp" id="dth" style="display:none" alt=""/>'
+'<input type="file" accept="image/png" id="di" onchange="hfs(this,\'d\')"/></div></div>'

+'<div class="fg"><label class="fl"><span data-i18n="lb_pwd"></span> <span style="font-weight:300;font-size:.8rem" data-i18n="pw_if"></span></label>'
+'<input type="password" class="fi pi" id="dp" placeholder="••••••••" autocomplete="off"/>'
+'<p class="ph" data-i18n="pw_hintd"></p></div>'

+'<button type="submit" class="bp" id="db"><span data-i18n="btn_dec"></span></button>'
+'</form><div class="ra" id="dr"></div></div></div>'

+'<div class="ip"><div class="cd">'
+'<h3 class="it">' + SR + ' <span data-i18n="it_dec"></span></h3>'
+'<p class="ix" data-i18n="id1"></p><p class="ix" data-i18n="id2"></p>'
+'<p class="ix" data-i18n="id3"></p><p class="ix" data-i18n="id4"></p>'
+'<div class="sb">' + EY + '<p data-i18n="sd"></p></div>'
+'</div></div></div></div>'

+'<footer>'
+'<p data-i18n="footer"></p>'
+'<p class="fds">' + GH + ' <a href="https://github.com/radmehr2025/Maskoot" target="_blank" rel="noopener" data-i18n="ft_src"></a></p>'
+'<p class="fds">' + ST + ' <span data-i18n="ft_star"></span></p>'
+'</footer>'
+'</div></div>'
+'<script>'
+'var ck=\'' + CK.replace(/'/g, "\\'") + '\',xk=\'' + XX.replace(/'/g, "\\'") + '\';'

+'(function(){var c=document.getElementById("gc"),x=c.getContext("2d"),w,h,s=[];function rz(){w=c.width=innerWidth;h=c.height=innerHeight}function cr(){s=[];for(var i=0;i<25;i++)s.push({x:Math.random()*w,y:Math.random()*h,sz:20+Math.random()*60,rot:Math.random()*Math.PI*2,rs:(Math.random()-.5)*.003,vx:(Math.random()-.5)*.3,vy:(Math.random()-.5)*.3,t:Math.floor(Math.random()*4),op:1,lw:.5+Math.random()})}function dr(o){x.save();x.translate(o.x,o.y);x.rotate(o.rot);x.strokeStyle=getComputedStyle(document.documentElement).getPropertyValue("--geo").trim();x.lineWidth=o.lw;x.beginPath();switch(o.t){case 0:for(var i=0;i<3;i++){var a=i*2*Math.PI/3-Math.PI/2;i===0?x.moveTo(Math.cos(a)*o.sz,Math.sin(a)*o.sz):x.lineTo(Math.cos(a)*o.sz,Math.sin(a)*o.sz)}x.closePath();break;case 1:x.rect(-o.sz/2,-o.sz/2,o.sz,o.sz);break;case 2:for(var i=0;i<6;i++){var a=i*Math.PI/3;i===0?x.moveTo(Math.cos(a)*o.sz*.6,Math.sin(a)*o.sz*.6):x.lineTo(Math.cos(a)*o.sz*.6,Math.sin(a)*o.sz*.6)}x.closePath();break;case 3:x.arc(0,0,o.sz*.5,0,Math.PI*2)}x.stroke();x.restore()}function ln(){var cl=getComputedStyle(document.documentElement).getPropertyValue("--geo-line").trim();for(var i=0;i<s.length;i++)for(var j=i+1;j<s.length;j++){var dx=s[i].x-s[j].x,dy=s[i].y-s[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<200){x.strokeStyle=cl;x.globalAlpha=(1-d/200);x.lineWidth=.5;x.beginPath();x.moveTo(s[i].x,s[i].y);x.lineTo(s[j].x,s[j].y);x.stroke();x.globalAlpha=1}}}function an(){x.clearRect(0,0,w,h);s.forEach(function(o){o.x+=o.vx;o.y+=o.vy;o.rot+=o.rs;if(o.x<-o.sz)o.x=w+o.sz;if(o.x>w+o.sz)o.x=-o.sz;if(o.y<-o.sz)o.y=h+o.sz;if(o.y>h+o.sz)o.y=-o.sz;dr(o)});ln();requestAnimationFrame(an)}addEventListener("resize",rz);rz();cr();an()})();'

+'var eM="text",cL="fa";'

+'var L={fa:{'
+'title:"مسکوت",'
+'slogan:"آنچه نباید گفت، در تصویر پنهان می\u200Cشود",'
+'tab_encode:"مخفی\u200Cسازی",'
+'tab_decode:"خواندن پیام",'
+'lb_img:"تصویر",'
+'lb_imgd:"تصویر حاوی محتوا",'
+'lb_msg:"متن محرمانه",'
+'lb_hf:"فایل مورد نظر",'
+'lb_pw:"رمز عبور",'
+'pw_opt:"(اختیاری)",'
+'lb_pwd:"رمز عبور",'
+'pw_if:"(در صورت وجود)",'
+'up_hint:"تصویر PNG یا JPG خود را انتخاب یا رها کنید",'
+'up_hintd:"تصویر PNG حاوی محتوا را انتخاب یا رها کنید",'
+'up_fmt:"فرمت مجاز: PNG و JPG — حداکثر ۱۵ مگابایت",'
+'up_fmtd:"فرمت مجاز: PNG — حداکثر ۱۵ مگابایت",'
+'up_fhint:"فایلی که می\u200Cخواهید مخفی کنید را انتخاب کنید",'
+'up_ffmt:"هر نوع فایلی قابل پذیرش است",'
+'m_text:"متن",'
+'m_file:"فایل",'
+'ph_msg:"متن مخفی خود را اینجا بنویسید...",'
+'pw_hint:"با تعیین رمز، محتوا با AES-256-GCM رمزنگاری می\u200Cشود",'
+'pw_hintd:"اگر محتوا رمزنگاری شده باشد، رمز عبور لازم است",'
+'btn_enc:"مخفی\u200Cسازی در تصویر",'
+'btn_dec:"خواندن از تصویر",'
+'it_enc:"مخفی\u200Cسازی پیام و فایل",'
+'it_dec:"خواندن پیام و استخراج فایل",'
+'ie1:"متن یا فایلت رو نامرئی داخل یه عکس PNG قایم کن؛ بدون اینکه ظاهر عکس حتی یه ذره تغییر کنه.",'
+'ie2:"اگر بخوای، می\u200Cتونی برای پیام یا فایلت رمز بذاری. در این صورت، محتوا با AES-256-GCM قفل می\u200Cشه و کلیدش با PBKDF2 ساخته می\u200Cشه.",'
+'ie3:"عکس خروجی ظاهراً هیچ فرقی با اصلی نداره و هرجا خواستی به اشتراک بذار.",'
+'ie4:"یک اثر انگشت دیجیتال (SHA-256) اضافه می\u200Cشه تا هر تغییری فوراً مشخص بشه.",'
+'id1:"عکس PNG حاوی محتوای مخفی رو آپلود کن تا پیام یا فایل پنهان استخراج بشه.",'
+'id2:"اگر محتوا رمزدار باشه، باید همون رمز رو وارد کنی.",'
+'id3:"صحت و یکپارچگی محتوا قبل از نمایش بررسی می\u200Cشه.",'
+'id4:"فقط عکس\u200Cهای ساخته\u200Cشده با مسکوت قابل استخراج هستن.",'
+'se:"همه فرایندها با Web Crypto API انجام می\u200Cشن. هیچ عکس، متن یا فایلی ذخیره نمی\u200Cشه. کد منبع کاملاً بازه.",'
+'sd:"مسکوت هیچ محتوایی نگه نمی\u200Cداره؛ همه\u200Cچیز لحظه\u200Cای پردازش و پاک می\u200Cشه. ارتباط از طریق HTTPS رمزنگاری شده.",'
+'footer:"مسکوت — ابزار استگانوگرافی متن\u200Cباز و رایگان",'
+'ft_src:"سورس پروژه در گیت\u200Cهاب",'
+'ft_star:"لطفا با ستاره دادن به این پروژه از توسعه آن حمایت کنید.",'
+'proc:"در حال پردازش...",'
+'ok_enc:"متن با موفقیت مخفی شد!",'
+'ok_encf:"فایل با موفقیت مخفی شد!",'
+'ok_dec:"پیام مخفی خوانده شد:",'
+'ok_decf:"فایل مخفی استخراج شد:",'
+'dl_img:"دانلود تصویر",'
+'dl_file:"دانلود فایل",'
+'cp:"کپی متن",'
+'cpd:"کپی شد!",'
+'e_img:"لطفاً یک تصویر انتخاب کنید.",'
+'e_msg:"لطفاً متن محرمانه را وارد کنید.",'
+'e_file:"لطفاً فایل را انتخاب کنید.",'
+'e_gen:"خطایی رخ داد. دوباره تلاش کنید."'
+'},en:{'
+'title:"Maskoot",'
+'slogan:"What must not be said, hides within the image",'
+'tab_encode:"Hide",'
+'tab_decode:"Read",'
+'lb_img:"Image",'
+'lb_imgd:"Image with hidden content",'
+'lb_msg:"Secret Message",'
+'lb_hf:"File to Hide",'
+'lb_pw:"Password",'
+'pw_opt:"(optional)",'
+'lb_pwd:"Password",'
+'pw_if:"(if set)",'
+'up_hint:"Select or drop your PNG or JPG image",'
+'up_hintd:"Select or drop the PNG with hidden content",'
+'up_fmt:"Formats: PNG & JPG — Max 15MB",'
+'up_fmtd:"Format: PNG — Max 15MB",'
+'up_fhint:"Select the file you want to hide",'
+'up_ffmt:"Any file type accepted",'
+'m_text:"Text",'
+'m_file:"File",'
+'ph_msg:"Type your secret message here...",'
+'pw_hint:"Password encrypts content with AES-256-GCM",'
+'pw_hintd:"Required if content was encrypted",'
+'btn_enc:"Hide in Image",'
+'btn_dec:"Read from Image",'
+'it_enc:"Hide Message & File",'
+'it_dec:"Read Message & Extract File",'
+'ie1:"Hide your text or file invisibly inside a PNG image — no visible change at all.",'
+'ie2:"Set a password to lock content with AES-256-GCM. Key is derived via PBKDF2.",'
+'ie3:"Output image looks identical to the original. Share it anywhere.",'
+'ie4:"A SHA-256 fingerprint is added so any tampering is immediately detectable.",'
+'id1:"Upload the PNG with hidden text or file to extract the concealed content.",'
+'id2:"If password-protected, enter the same password.",'
+'id3:"Integrity is verified before displaying content.",'
+'id4:"Only Maskoot-created images can be extracted.",'
+'se:"All processes use Web Crypto API. No data is stored. Source code is fully open.",'
+'sd:"Maskoot keeps nothing; real-time processing, then wiped. HTTPS encrypted connection.",'
+'footer:"Maskoot — Free & open-source steganography tool",'
+'ft_src:"Project source on GitHub",'
+'ft_star:"Please support this project by giving it a star.",'
+'proc:"Processing...",'
+'ok_enc:"Message hidden successfully!",'
+'ok_encf:"File hidden successfully!",'
+'ok_dec:"Hidden message read:",'
+'ok_decf:"Hidden file extracted:",'
+'dl_img:"Download Image",'
+'dl_file:"Download File",'
+'cp:"Copy Text",'
+'cpd:"Copied!",'
+'e_img:"Please select an image.",'
+'e_msg:"Please enter a message.",'
+'e_file:"Please select a file.",'
+'e_gen:"An error occurred. Try again."'
+'}};'

+'function setLang(l){cL=l;var h=document.documentElement;h.setAttribute("dir",l==="fa"?"rtl":"ltr");h.setAttribute("lang",l);document.querySelectorAll("[data-lang]").forEach(function(b){b.classList.toggle("act",b.dataset.lang===l)});var s=L[l];document.querySelectorAll("[data-i18n]").forEach(function(e){var k=e.dataset.i18n;if(s[k]!==undefined)e.textContent=s[k]});document.querySelectorAll("[data-i18n-ph]").forEach(function(e){var k=e.dataset.i18nPh;if(s[k]!==undefined)e.placeholder=s[k]});document.title=l==="fa"?"مسکوت | Maskoot":"Maskoot"}'

+'function setTheme(t){document.documentElement.setAttribute("data-theme",t);document.querySelectorAll("[data-theme]").forEach(function(b){b.classList.toggle("act",b.dataset.theme===t)});try{localStorage.setItem("maskoot-theme",t)}catch(e){}}'

+'function sTab(t){document.querySelectorAll(".tab").forEach(function(b){b.classList.toggle("act",b.dataset.tab===t)});document.querySelectorAll(".tc").forEach(function(c){c.classList.toggle("ac",c.id==="tab-"+t)})}'

+'function sMode(m){eM=m;document.querySelectorAll(".mb").forEach(function(b){b.classList.toggle("act",b.dataset.mode===m)});document.getElementById("tig").classList.toggle("hd",m!=="text");document.getElementById("fig").classList.toggle("hd",m!=="file")}'

+'function hfs(inp,p){var f=inp.files[0],n=document.getElementById(p==="e"?"efn":"dfn"),t=document.getElementById(p==="e"?"eth":"dth"),u=document.getElementById(p==="e"?"eu":"du");if(f){n.textContent=f.name+" ("+(f.size/1024).toFixed(1)+" KB)";n.style.display="block";u.classList.add("hf");var r=new FileReader();r.onload=function(e){t.src=e.target.result;t.style.display="inline-block"};r.readAsDataURL(f)}else{n.style.display="none";t.style.display="none";u.classList.remove("hf")}}'

+'function hhfs(inp){var f=inp.files[0],n=document.getElementById("hfn"),u=document.getElementById("hfu");if(f){n.textContent=f.name+" ("+(f.size/1024).toFixed(1)+" KB)";n.style.display="block";u.classList.add("hf")}else{n.style.display="none";u.classList.remove("hf")}}'

+'["eu","du","hfu"].forEach(function(id){var el=document.getElementById(id);if(!el)return;el.addEventListener("dragover",function(e){e.preventDefault();el.classList.add("dg")});el.addEventListener("dragleave",function(){el.classList.remove("dg")});el.addEventListener("drop",function(e){e.preventDefault();el.classList.remove("dg");var inp=el.querySelector("input[type=file]");if(e.dataTransfer.files.length){inp.files=e.dataTransfer.files;inp.dispatchEvent(new Event("change"))}})});'

+'async function doEnc(e){e.preventDefault();var s=L[cL],ii=document.getElementById("ei"),b=document.getElementById("eb"),ra=document.getElementById("er");if(!ii.files[0])return sErr(ra,s.e_img);var fd=new FormData();fd.append("image",ii.files[0]);fd.append("password",document.getElementById("ep").value);fd.append("lang",cL);fd.append("mode",eM);if(eM==="text"){var m=document.getElementById("em").value.trim();if(!m)return sErr(ra,s.e_msg);fd.append("message",m)}else{var hf=document.getElementById("ehf");if(!hf.files[0])return sErr(ra,s.e_file);fd.append("hiddenFile",hf.files[0])}b.disabled=true;b.innerHTML="<span class=\\"sp\\"></span> "+s.proc;ra.classList.remove("v");try{var r=await fetch("/api/encode",{method:"POST",body:fd});if(r.ok){var bl=await r.blob(),u=URL.createObjectURL(bl),sm=eM==="file"?s.ok_encf:s.ok_enc;ra.innerHTML="<div class=\\"rs\\"><div class=\\"rh\\">"+ck+sm+"</div><div class=\\"rac\\"><a href=\\""+u+"\\" download=\\"maskoot_encoded.png\\" class=\\"bs\\">"+s.dl_img+"</a></div></div>";ra.classList.add("v")}else{var d=await r.json();sErr(ra,d.message||s.e_gen)}}catch(x){sErr(ra,s.e_gen)}finally{b.disabled=false;b.innerHTML="<span data-i18n=\\"btn_enc\\">"+s.btn_enc+"</span>"}}'

+'async function doDec(e){e.preventDefault();var s=L[cL],ii=document.getElementById("di"),b=document.getElementById("db"),ra=document.getElementById("dr");if(!ii.files[0])return sErr(ra,s.e_img);var fd=new FormData();fd.append("image",ii.files[0]);fd.append("password",document.getElementById("dp").value);fd.append("lang",cL);b.disabled=true;b.innerHTML="<span class=\\"sp\\"></span> "+s.proc;ra.classList.remove("v");try{var r=await fetch("/api/decode",{method:"POST",body:fd}),d=await r.json();if(!d.error){if(d.type==="file"){var bs=atob(d.fileData),ab=new Uint8Array(bs.length);for(var i=0;i<bs.length;i++)ab[i]=bs.charCodeAt(i);var bl=new Blob([ab]),u=URL.createObjectURL(bl);ra.innerHTML="<div class=\\"rs\\"><div class=\\"rh\\">"+ck+s.ok_decf+" "+d.fileName+"</div><div class=\\"rac\\"><a href=\\""+u+"\\" download=\\""+d.fileName+"\\" class=\\"bs\\">"+s.dl_file+"</a></div></div>"}else{var em=d.message.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");ra.innerHTML="<div class=\\"rs\\"><div class=\\"rh\\">"+ck+s.ok_dec+"</div><div class=\\"rm\\">"+em+"</div><div class=\\"rac\\"><button class=\\"bs\\" onclick=\\"cpTx(this)\\">"+s.cp+"</button></div></div>";ra._t=d.message}ra.classList.add("v")}else sErr(ra,d.message||s.e_gen)}catch(x){sErr(ra,s.e_gen)}finally{b.disabled=false;b.innerHTML="<span data-i18n=\\"btn_dec\\">"+s.btn_dec+"</span>"}}'

+'function sErr(a,m){a.innerHTML="<div class=\\"re\\"><div class=\\"rh\\">"+xk+m+"</div></div>";a.classList.add("v")}'

+'function cpTx(b){var s=L[cL],t=document.getElementById("dr")._t||"";navigator.clipboard.writeText(t).then(function(){var o=b.textContent;b.textContent=s.cpd;setTimeout(function(){b.textContent=o},1500)})}'

+'(function(){try{var t=localStorage.getItem("maskoot-theme");if(t)setTheme(t);else if(matchMedia("(prefers-color-scheme:dark)").matches)setTheme("dark")}catch(e){}})();'
+'setLang("fa");'

+'<\/script></body></html>';
}