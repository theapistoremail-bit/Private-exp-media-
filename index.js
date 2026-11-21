import { createRemoteJWKSet, jwtVerify } from 'jose';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const MAX_JSON = 100_000;

function securityHeaders(response) {
  const h = new Headers(response.headers);
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  h.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
}

async function authenticate(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD || env.ACCESS_AUD.startsWith('REPLACE_')) throw new Error('AUTH_REQUIRED');
  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  const jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, jwks, { issuer, audience: env.ACCESS_AUD });
  return String(payload.email || payload.sub || 'authorized-user');
}

async function audit(env, actor, action, type, resourceId = '', details = '') {
  await env.DB.prepare('INSERT INTO audit_log (id,actor,action,resource_type,resource_id,details,created_at) VALUES (?,?,?,?,?,?,?)')
    .bind(id(), actor, action, type, resourceId, String(details).slice(0, 2000), now()).run();
}

async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_JSON) throw new Error('BODY_TOO_LARGE');
  return request.json();
}

function validIOC(type, value) {
  const v = String(value || '').trim();
  if (!v || v.length > 2048) return false;
  if (type === 'ipv4') return /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(v);
  if (type === 'domain') return /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(v);
  if (type === 'sha256') return /^[a-fA-F0-9]{64}$/.test(v);
  if (type === 'url') { try { const u = new URL(v); return ['http:', 'https:'].includes(u.protocol); } catch { return false; } }
  if (type === 'email') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  return false;
}

async function analyzeWithAI(env, prompt) {
  if (!env.DEEPSEEK_API_KEY) throw new Error('DEEPSEEK_NOT_CONFIGURED');
  const system = `Eres un analista de ciberinteligencia defensiva. Analiza exclusivamente el material aportado. No afirmes haber accedido a redes, sistemas, dark web ni fuentes externas. Distingue HECHOS OBSERVADOS, HIPÓTESIS e INFORMACIÓN NO VERIFICADA. No inventes CVE, IOC, fuentes, fechas ni atribuciones. No proporciones instrucciones para intrusión, robo de credenciales, malware o evasión. Recomienda validación defensiva y preservación de evidencias.`;
  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${env.DEEPSEEK_API_KEY}` },
    body: JSON.stringify({ model: 'deepseek-chat', messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }], temperature: 0.2, stream: false })
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`AI_UPSTREAM_${response.status}`);
  return data.choices?.[0]?.message?.content || 'Sin respuesta del modelo.';
}

async function createPdf(title, sections) {
  const pdf = await PDFDocument.create();
  let page = pdf.addPage([595.28, 841.89]);
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  let y = 790;
  const draw = (text, isBold = false, size = 10) => {
    const lines = String(text ?? '').replace(/[\r\t]/g, ' ').split('\n');
    for (const line of lines) {
      const chunks = line.match(/.{1,92}(?:\s|$)/g) || [''];
      for (const chunk of chunks) {
        if (y < 55) { page = pdf.addPage([595.28, 841.89]); y = 790; }
        page.drawText(chunk.trim(), { x: 48, y, size, font: isBold ? bold : font, color: rgb(0.12, 0.15, 0.19), maxWidth: 500 });
        y -= size + 6;
      }
    }
  };
  draw('PRIVATE INTELLIGENCE PLATFORM', true, 9); y -= 10;
  draw(title, true, 20); y -= 12;
  draw(`Generado: ${now()}`); y -= 12;
  for (const section of sections) { draw(section.heading, true, 13); draw(section.body, false, 10); y -= 10; }
  draw('Nota: este informe resume únicamente la información almacenada en la plataforma. Las hipótesis requieren validación independiente.', false, 8);
  return pdf.save();
}

async function handleApi(request, env, actor, url) {
  const path = url.pathname;
  if (request.method === 'GET' && path === '/api/health') return json({ ok: true, service: 'private-intelligence-platform', time: now() });
  if (request.method === 'GET' && path === '/api/dashboard') {
    const [cases, iocs, evidence, high] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) n FROM cases WHERE status != 'closed'").first(),
      env.DB.prepare('SELECT COUNT(*) n FROM iocs').first(),
      env.DB.prepare('SELECT COUNT(*) n FROM evidence').first(),
      env.DB.prepare("SELECT COUNT(*) n FROM iocs WHERE severity='high' OR severity='critical'").first()
    ]);
    const recent = await env.DB.prepare('SELECT id,type,value,severity,status,created_at FROM iocs ORDER BY created_at DESC LIMIT 8').all();
    return json({ metrics: { activeCases: cases.n, totalIOCs: iocs.n, evidenceItems: evidence.n, highRisk: high.n }, recentIOCs: recent.results });
  }
  if (request.method === 'GET' && path === '/api/cases') {
    const result = await env.DB.prepare('SELECT * FROM cases ORDER BY updated_at DESC LIMIT 200').all(); return json(result.results);
  }
  if (request.method === 'POST' && path === '/api/cases') {
    const b = await readJson(request); if (!String(b.title || '').trim()) return json({ error: 'El título es obligatorio.' }, 400);
    const caseId = id(), t = now();
    await env.DB.prepare('INSERT INTO cases (id,title,description,status,classification,created_at,updated_at,created_by) VALUES (?,?,?,?,?,?,?,?)')
      .bind(caseId, String(b.title).slice(0,180), String(b.description || '').slice(0,5000), 'open', ['internal','confidential','restricted'].includes(b.classification) ? b.classification : 'internal', t, t, actor).run();
    await audit(env, actor, 'case.created', 'case', caseId); return json({ id: caseId }, 201);
  }
  if (request.method === 'GET' && path === '/api/iocs') {
    const result = await env.DB.prepare('SELECT * FROM iocs ORDER BY created_at DESC LIMIT 500').all(); return json(result.results);
  }
  if (request.method === 'POST' && path === '/api/iocs') {
    const b = await readJson(request); const type = String(b.type || '').toLowerCase(); const value = String(b.value || '').trim();
    if (!validIOC(type, value)) return json({ error: 'Indicador inválido o tipo no admitido.' }, 400);
    const severity = ['low','medium','high','critical'].includes(b.severity) ? b.severity : 'medium';
    const confidence = Math.max(0, Math.min(100, Number(b.confidence ?? 50)));
    const normalized = type === 'domain' ? value.toLowerCase() : type === 'email' ? value.toLowerCase() : value;
    const iocId = id();
    try {
      await env.DB.prepare('INSERT INTO iocs (id,type,value,normalized_value,severity,confidence,status,source,notes,case_id,first_seen,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .bind(iocId,type,value,normalized,severity,confidence,['verified','observed','inferred','pending'].includes(b.status) ? b.status : 'observed',String(b.source || '').slice(0,300),String(b.notes || '').slice(0,3000),b.case_id || null,now(),now()).run();
    } catch { return json({ error: 'El indicador ya existe o la referencia al expediente no es válida.' }, 409); }
    await audit(env, actor, 'ioc.created', 'ioc', iocId); return json({ id: iocId }, 201);
  }
  if (request.method === 'POST' && path === '/api/analyze') {
    const b = await readJson(request); const prompt = String(b.prompt || '').trim();
    if (!prompt || prompt.length > 12000) return json({ error: 'El texto debe tener entre 1 y 12000 caracteres.' }, 400);
    try { const result = await analyzeWithAI(env, prompt); await audit(env, actor, 'analysis.created', 'analysis', '', `chars=${prompt.length}`); return json({ analysis: result, disclaimer: 'Análisis asistido por IA; no constituye evidencia verificada.' }); }
    catch (e) { return json({ error: e.message === 'DEEPSEEK_NOT_CONFIGURED' ? 'Falta configurar DEEPSEEK_API_KEY.' : 'No fue posible completar el análisis.' }, 502); }
  }
  if (request.method === 'POST' && path === '/api/evidence') {
    const form = await request.formData(); const file = form.get('file'); const caseId = String(form.get('case_id') || '');
    if (!(file instanceof File) || !caseId) return json({ error: 'Se requiere archivo y expediente.' }, 400);
    if (file.size < 1 || file.size > 10 * 1024 * 1024) return json({ error: 'El archivo debe pesar entre 1 byte y 10 MB.' }, 400);
    const exists = await env.DB.prepare('SELECT id FROM cases WHERE id=?').bind(caseId).first(); if (!exists) return json({ error: 'Expediente no encontrado.' }, 404);
    const bytes = await file.arrayBuffer(); const digest = await crypto.subtle.digest('SHA-256', bytes);
    const sha256 = [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2,'0')).join('');
    const evidenceId = id(), key = `${caseId}/${evidenceId}`;
    await env.EVIDENCE.put(key, bytes, { httpMetadata: { contentType: file.type || 'application/octet-stream' }, customMetadata: { sha256, originalName: file.name.slice(0,255) } });
    await env.DB.prepare('INSERT INTO evidence (id,case_id,filename,content_type,size,sha256,r2_key,description,collected_at,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .bind(evidenceId,caseId,file.name.slice(0,255),file.type || 'application/octet-stream',file.size,sha256,key,String(form.get('description') || '').slice(0,1000),now(),now(),actor).run();
    await audit(env, actor, 'evidence.uploaded', 'evidence', evidenceId, `sha256=${sha256}`); return json({ id: evidenceId, sha256 }, 201);
  }
  if (request.method === 'GET' && path === '/api/evidence') {
    const caseId = url.searchParams.get('case_id'); if (!caseId) return json({ error: 'case_id requerido.' }, 400);
    const result = await env.DB.prepare('SELECT id,case_id,filename,content_type,size,sha256,description,collected_at,created_at,created_by FROM evidence WHERE case_id=? ORDER BY created_at DESC').bind(caseId).all(); return json(result.results);
  }
  if (request.method === 'GET' && path === '/api/audit') {
    const result = await env.DB.prepare('SELECT actor,action,resource_type,resource_id,details,created_at FROM audit_log ORDER BY created_at DESC LIMIT 200').all(); return json(result.results);
  }
  if (request.method === 'POST' && path === '/api/reports') {
    const b = await readJson(request); const title = String(b.title || 'Informe de investigación').slice(0,180);
    const caseId = String(b.case_id || ''); let sections = [];
    if (caseId) {
      const c = await env.DB.prepare('SELECT * FROM cases WHERE id=?').bind(caseId).first(); if (!c) return json({ error: 'Expediente no encontrado.' }, 404);
      const iocs = await env.DB.prepare('SELECT type,value,severity,confidence,status,source,notes,created_at FROM iocs WHERE case_id=?').bind(caseId).all();
      const ev = await env.DB.prepare('SELECT filename,sha256,size,content_type,collected_at FROM evidence WHERE case_id=?').bind(caseId).all();
      sections = [{ heading: 'Expediente', body: `${c.title}\nEstado: ${c.status}\nClasificación: ${c.classification}\nDescripción: ${c.description}` }, { heading: 'Indicadores', body: iocs.results.length ? iocs.results.map(x => `${x.type}: ${x.value} | severidad=${x.severity} | confianza=${x.confidence}% | estado=${x.status} | fuente=${x.source}`).join('\n') : 'No hay indicadores asociados.' }, { heading: 'Evidencias', body: ev.results.length ? ev.results.map(x => `${x.filename} | ${x.size} bytes | SHA-256: ${x.sha256} | ${x.collected_at}`).join('\n') : 'No hay evidencias adjuntas.' }];
    } else { sections = [{ heading: 'Resumen', body: String(b.summary || 'Sin resumen proporcionado.').slice(0,6000) }, { heading: 'Metodología y limitaciones', body: String(b.methodology || 'Describir fuentes, alcance, fechas y limitaciones.').slice(0,4000) }, { heading: 'Hallazgos y recomendaciones', body: String(b.findings || 'No se han agregado hallazgos.').slice(0,6000) }]; }
    const bytes = await createPdf(title, sections); await audit(env, actor, 'report.generated', 'report', caseId); return new Response(bytes, { headers: { 'content-type': 'application/pdf', 'content-disposition': 'attachment; filename="intelligence-report.pdf"', 'cache-control': 'no-store' } });
  }
  return json({ error: 'Ruta no encontrada.' }, 404);
}

export default {
  async fetch(request, env) {
    let response;
    try {
      const url = new URL(request.url);
      if (!url.pathname.startsWith('/api/')) response = await env.ASSETS.fetch(request);
      else {
        const origin = request.headers.get('Origin');
        if (origin && origin !== url.origin) response = json({ error: 'Origen no permitido.' }, 403);
        else {
          let actor;
          try { actor = await authenticate(request, env); }
          catch { response = json({ error: 'Acceso privado requerido. Inicia sesión mediante Cloudflare Access.' }, 401); }
          if (actor) {
            if (request.method === 'OPTIONS') response = new Response(null, { status: 204, headers: { 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
            else response = await handleApi(request, env, actor, url);
          }
        }
      }
    } catch (e) {
      const status = e.message === 'BODY_TOO_LARGE' ? 413 : 400;
      response = json({ error: status === 413 ? 'Solicitud demasiado grande.' : 'Solicitud inválida o error interno.' }, status);
    }
    return securityHeaders(response || json({ error: 'Error interno.' }, 500));
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await env.DB.prepare("INSERT INTO audit_log (id,actor,action,resource_type,resource_id,details,created_at) VALUES (?,?,?,?,?,?,?)")
        .bind(id(), 'system', 'scheduler.tick', 'scheduler', '', `cron=${event.cron}`, now()).run();
    })());
  }
};
