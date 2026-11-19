// AKSHAY CREATION worker. Needs secret AUTH_SECRET (add it in Cloudflare: Worker > Settings > Variables and Secrets)
const enc = new TextEncoder();
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
const err = (m, s = 400) => json({ error: m }, s);
const clip = (s, n = 500) => String(s ?? "").trim().slice(0, n);
// allows normal https links and photos uploaded through the portal (/img/...)
const http = (u) => (/^https?:\/\//i.test(u) ? clip(u, 1000) : /^\/img\/[a-f0-9-]{36}$/i.test(u) ? u : "");
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const same = (a, b) => { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };

async function sign(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
async function makeToken(env, u, r) {
  const p = b64u(enc.encode(JSON.stringify({ u, r, exp: Date.now() + 12 * 3600e3 })));
  return p + "." + (await sign(env.AUTH_SECRET, p));
}
async function readToken(env, req) {
  const [p, s] = (req.headers.get("Authorization") || "").slice(7).split(".");
  if (!p || !s || !same(s, await sign(env.AUTH_SECRET, p))) return null;
  try { const d = JSON.parse(new TextDecoder().decode(unb64u(p))); return d.exp > Date.now() ? d : null; } catch { return null; }
}
async function hashPw(pw, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, k, 256);
  return "pbkdf2$" + b64u(salt) + "$" + b64u(bits);
}
// Old plaintext passwords still work once, then get upgraded to a hash automatically.
async function checkPw(pw, stored) {
  stored = String(stored || "");
  if (!stored.startsWith("pbkdf2$")) return same(pw, stored) ? "legacy" : false;
  return same(await hashPw(pw, unb64u(stored.split("$")[1])), stored) ? "ok" : false;
}

const hits = new Map();
const limited = (key, max, ms) => { const n = Date.now(), a = (hits.get(key) || []).filter((t) => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; };

// Only these tables and columns can ever be written from the admin panel.
const T = {
  creators: { t: "creators", cols: ["name", "platform", "handle", "profile_url", "avatar_url", "bio", "status"], url: ["profile_url", "avatar_url"], def: { status: "approved", platform: "YouTube" } },
  ads: { t: "ads", cols: ["title", "badge", "media_url", "target_url", "sort", "active"], num: ["sort", "active"], url: ["media_url", "target_url"], def: { active: 1, sort: 0 } },
  products: { t: "products", cols: ["title", "category", "description", "price_inr", "image_url", "download_url", "active"], num: ["price_inr", "active"], url: ["image_url", "download_url"], def: { active: 1 } },
  charity: { t: "charity_campaigns", cols: ["title", "banner_url", "target_amount", "raised_amount", "upi_id", "upi_name", "donate_link", "description", "active"], num: ["target_amount", "raised_amount", "active"], url: ["banner_url", "donate_link"], def: { active: 1 } },
  polls: { t: "polls", cols: ["question", "options", "active"], num: ["active"], def: { active: 1 } },
  orders: { t: "orders", cols: [] },
  bookings: { t: "bookings", cols: [] },
  care: { t: "care_cases", cols: [] },
  staff: { t: "staff_users", cols: [] },
};
const STATUS = { orders: ["PENDING", "PAID", "REJECTED"], bookings: ["pending", "contacted", "done"], care: ["pending", "in_progress", "resolved"], creators: ["pending", "approved"] };

let ready;
const init = (db) => (ready ||= (async () => {
  for (const q of [
    "CREATE TABLE IF NOT EXISTS poll_votes (poll_id INTEGER, voter TEXT, option_index INTEGER, PRIMARY KEY (poll_id, voter))",
    "ALTER TABLE polls ADD COLUMN active INTEGER DEFAULT 1",
    "ALTER TABLE polls ADD COLUMN options TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE polls ADD COLUMN counts TEXT NOT NULL DEFAULT '[]'",
    "CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, mime TEXT, data TEXT)",
    "CREATE TABLE IF NOT EXISTS live_sessions (session_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL)",
  ]) {
    try { await db.prepare(q).run(); } catch (e) {}
  }
})());

// ---- photo upload (stored inside the D1 database, no extra setup) ----
async function serveImage(db, id) {
  const r = await db.prepare("SELECT mime, data FROM images WHERE id = ?").bind(id).first();
  if (!r) return new Response("Not found", { status: 404 });
  const bin = atob(r.data), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return new Response(u, { headers: { "Content-Type": r.mime, "Cache-Control": "public, max-age=31536000, immutable" } });
}
async function saveImage(db, body) {
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(body.data || ""));
  if (!m) return err("Send a JPG, PNG or WEBP photo");
  if (m[2].length > 1600000) return err("Photo is too large");
  const id = crypto.randomUUID();
  await db.prepare("INSERT INTO images (id, mime, data) VALUES (?, ?, ?)").bind(id, m[1], m[2]).run();
  return json({ url: "/img/" + id });
}

async function adminWrite(db, sub, body, me) {
  const cfg = T[sub];
  if (!cfg) return err("Not Found", 404);
  if (sub === "staff" && me.r === "moderator") return err("Admins only", 403);
  const { action, id, data = {}, status } = body;

  if (action === "delete") {
    if (!id) return err("Missing id");
    if (sub === "polls") await db.prepare("DELETE FROM poll_votes WHERE poll_id = ?").bind(id).run();
    await db.prepare(`DELETE FROM ${cfg.t} WHERE id = ?`).bind(id).run();
    return json({ success: true });
  }
  if (action === "status") {
    if (!id || !STATUS[sub]?.includes(status)) return err("Invalid status");
    await db.prepare(`UPDATE ${cfg.t} SET status = ? WHERE id = ?`).bind(status, id).run();
    return json({ success: true });
  }
  if (action !== "create" && action !== "update") return err("Unknown action");

  if (sub === "staff") {
    const u = clip(data.username, 40), p = String(data.password || "");
    if (u.length < 3 || p.length < 8) return err("Username 3+ chars and password 8+ chars");
    const dup = await db.prepare("SELECT 1 AS x FROM admins WHERE username = ? UNION SELECT 1 FROM staff_users WHERE username = ?").bind(u, u).first();
    if (dup) return err("Username already exists", 409);
    await db.prepare("INSERT INTO staff_users (username, password, role) VALUES (?, ?, ?)").bind(u, await hashPw(p), data.role === "admin" ? "admin" : "moderator").run();
    return json({ success: true });
  }
  if (!cfg.cols.length) return err("Not editable");

  const row = {};
  for (const c of cfg.cols) {
    if (data[c] === undefined) continue;
    if (c === "options") continue;
    if (cfg.num?.includes(c)) row[c] = Number(data[c]) || 0;
    else if (cfg.url?.includes(c)) row[c] = http(String(data[c]));
    else row[c] = clip(data[c], c === "bio" || c === "description" ? 2000 : 500);
  }
  if (sub === "polls" && Array.isArray(data.options)) {
    const o = data.options.map((x) => clip(x, 120)).filter(Boolean).slice(0, 6);
    if (o.length < 2) return err("A poll needs 2 to 6 options");
    row.options = JSON.stringify(o);
    if (action === "create") row.counts = JSON.stringify(o.map(() => 0));
    else {
      const cur = await db.prepare("SELECT options, counts FROM polls WHERE id = ?").bind(id).first();
      if (cur && cur.options !== row.options) { row.counts = JSON.stringify(o.map(() => 0)); await db.prepare("DELETE FROM poll_votes WHERE poll_id = ?").bind(id).run(); }
    }
  }
  if (action === "create") {
    const r = { ...cfg.def, ...row };
    const k = Object.keys(r);
    if (!k.length) return err("Nothing to save");
    await db.prepare(`INSERT INTO ${cfg.t} (${k.join(",")}) VALUES (${k.map(() => "?").join(",")})`).bind(...k.map((c) => r[c])).run();
  } else {
    const k = Object.keys(row);
    if (!id || !k.length) return err("Nothing to update");
    await db.prepare(`UPDATE ${cfg.t} SET ${k.map((c) => c + " = ?").join(", ")} WHERE id = ?`).bind(...k.map((c) => row[c]), id).run();
  }
  return json({ success: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url), path = url.pathname, method = request.method;
    if (path.startsWith("/img/") && env.DB) { await init(env.DB); return serveImage(env.DB, path.slice(5)); }
    if (!path.startsWith("/api/")) return env.ASSETS ? env.ASSETS.fetch(request) : err("Not Found", 404);
    if (method === "OPTIONS") return new Response(null, { status: 204 });
    const db = env.DB;
    const ip = request.headers.get("CF-Connecting-IP") || "0";
    try {
      await init(db);
      const body = method === "POST" ? await request.json().catch(() => ({})) : {};

      if (path === "/api/public/presence" && method === "POST") {
        const session = String(body.session_id || "");
        if (!/^[0-9a-f-]{36}$/i.test(session)) return err("Invalid visitor session");
        if (limited("presence:" + ip, 30, 60e3)) return err("Please slow down", 429);
        const now = Date.now();
        await db.prepare("INSERT INTO live_sessions (session_id, last_seen) VALUES (?, ?) ON CONFLICT(session_id) DO UPDATE SET last_seen = excluded.last_seen").bind(session, now).run();
        await db.prepare("DELETE FROM live_sessions WHERE last_seen < ?").bind(now - 180000).run();
        const active = await db.prepare("SELECT COUNT(*) AS total FROM live_sessions WHERE last_seen >= ?").bind(now - 90000).first();
        return json({ active_visitors: Number(active?.total || 0) });
      }

      if (!env.AUTH_SECRET) return err("AUTH_SECRET is not set. Add it in Cloudflare: Worker > Settings > Variables and Secrets", 500);

      if (path === "/api/public/overview" && method === "GET") {
        const voter = await sign(env.AUTH_SECRET, "voter:" + ip);
        const [creators, ads, products, polls, charity, mine] = await Promise.all([
          db.prepare("SELECT id, name, platform, handle, profile_url, avatar_url, bio FROM creators WHERE status = 'approved' ORDER BY id DESC").all(),
          db.prepare("SELECT id, title, badge, media_url, target_url FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC").all(),
          db.prepare("SELECT id, title, category, description, price_inr, image_url FROM products WHERE active = 1 ORDER BY id DESC").all(),
          db.prepare("SELECT id, question, options, counts FROM polls WHERE COALESCE(active, 1) = 1 ORDER BY id DESC").all(),
          db.prepare("SELECT id, title, banner_url, target_amount, raised_amount, upi_id, upi_name, donate_link, description FROM charity_campaigns WHERE active = 1 ORDER BY id DESC").all(),
          db.prepare("SELECT poll_id, option_index FROM poll_votes WHERE voter = ?").bind(voter).all(),
        ]);
        const my = Object.fromEntries((mine.results || []).map((v) => [v.poll_id, v.option_index]));
        return json({
          creators: creators.results || [], ads: ads.results || [], products: products.results || [],
          charities: charity.results || [],
          polls: (polls.results || []).map((p) => {
            let o = [], c = [];
            try { o = JSON.parse(p.options || "[]"); } catch (e) {}
            try { c = JSON.parse(p.counts || "[]"); } catch (e) {}
            c = o.map((_, i) => +c[i] || 0);
            return { id: p.id, question: p.question, options: o, counts: c, total_votes: c.reduce((a, b) => a + b, 0), user_voted: my[p.id] ?? null };
          }),
        });
      }

      if (method === "POST" && ["/api/creators/apply", "/api/services/book", "/api/care/submit", "/api/checkout/upi-submit", "/api/polls/vote"].includes(path) && limited("f:" + ip, 20, 3600e3)) return err("Too many requests, try later", 429);

      if (path === "/api/creators/apply" && method === "POST") {
        const name = clip(body.name, 80), handle = clip(body.handle, 80), purl = http(String(body.profile_url || ""));
        if (!name || !handle || !purl) return err("Name, handle and a valid https profile link are required");
        await db.prepare("INSERT INTO creators (name, platform, handle, profile_url, avatar_url, bio, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')")
          .bind(name, ["YouTube", "Instagram", "Twitter"].includes(body.platform) ? body.platform : "YouTube", handle, purl, http(String(body.avatar_url || "")), clip(body.bio, 600)).run();
        return json({ success: true });
      }

      if (path === "/api/services/book" && method === "POST") {
        const email = clip(body.client_email, 120);
        if (!clip(body.client_name) || !/^\S+@\S+\.\S+$/.test(email) || !clip(body.details)) return err("Name, valid email and brief are required");
        await db.prepare("INSERT INTO bookings (service_type, client_name, client_email, client_contact, details, status) VALUES (?, ?, ?, ?, ?, 'pending')")
          .bind(clip(body.service_type, 60) || "General", clip(body.client_name, 100), email, clip(body.client_contact, 60), clip(body.details, 2000)).run();
        return json({ success: true });
      }

      if (path === "/api/care/submit" && method === "POST") {
        if (!clip(body.applicant_name) || !clip(body.private_details)) return err("Name and message are required");
        if (!body.consent_granted) return err("Please tick the consent box");
        await db.prepare("INSERT INTO care_cases (applicant_name, contact_info, case_title, private_details, consent_granted, status) VALUES (?, ?, ?, ?, 1, 'pending')")
          .bind(clip(body.applicant_name, 100), clip(body.contact_info, 120), clip(body.case_title, 150) || "Support Request", clip(body.private_details, 3000)).run();
        return json({ success: true });
      }

      if (path === "/api/checkout/upi-submit" && method === "POST") {
        const utr = String(body.utr || "");
        if (!/^\d{12}$/.test(utr)) return err("UTR number must be exactly 12 digits");
        if (!clip(body.customer_name)) return err("Name is required");
        const prod = await db.prepare("SELECT id FROM products WHERE id = ? AND active = 1").bind(body.product_id).first();
        if (!prod) return err("Product not available", 404);
        if (await db.prepare("SELECT 1 AS x FROM orders WHERE utr = ?").bind(utr).first()) return err("This UTR was already submitted", 409);
        const orderId = "AKC_" + b64u(crypto.getRandomValues(new Uint8Array(6))).replace(/[-_]/g, "X").toUpperCase();
        await db.prepare("INSERT INTO orders (order_id, product_id, customer_name, customer_email, utr, status) VALUES (?, ?, ?, ?, ?, 'PENDING')")
          .bind(orderId, prod.id, clip(body.customer_name, 100), clip(body.customer_email, 120), utr).run();
        return json({ success: true, order_id: orderId });
      }

      if (path === "/api/checkout/verify" && method === "GET") {
        if (limited("v:" + ip, 20, 600e3)) return err("Too many checks, try later", 429);
        const q = clip(url.searchParams.get("order_id"), 40);
        if (!q) return err("Order ID or UTR required");
        const o = await db.prepare("SELECT o.status, p.download_url FROM orders o LEFT JOIN products p ON o.product_id = p.id WHERE o.order_id = ? OR o.utr = ?").bind(q, q).first();
        if (!o) return err("Order not found", 404);
        return json({ status: o.status, download_url: o.status === "PAID" ? o.download_url : null });
      }

      if (path === "/api/polls/vote" && method === "POST") {
        const poll = await db.prepare("SELECT id, options, counts FROM polls WHERE id = ? AND COALESCE(active, 1) = 1").bind(body.poll_id).first();
        if (!poll) return err("Poll not found", 404);
        let o = [], c = [];
        try { o = JSON.parse(poll.options || "[]"); } catch (e) {}
        try { c = JSON.parse(poll.counts || "[]"); } catch (e) {}
        c = o.map((_, i) => +c[i] || 0);
        const idx = parseInt(body.option_index);
        if (!(idx >= 0 && idx < o.length)) return err("Invalid option");
        const voter = await sign(env.AUTH_SECRET, "voter:" + ip);
        try { await db.prepare("INSERT INTO poll_votes (poll_id, voter, option_index) VALUES (?, ?, ?)").bind(poll.id, voter, idx).run(); }
        catch (e) { return err("You already voted in this poll", 409); }
        c[idx]++;
        await db.prepare("UPDATE polls SET counts = ? WHERE id = ?").bind(JSON.stringify(c), poll.id).run();
        return json({ success: true });
      }

      if (path === "/api/auth/login" && method === "POST") {
        if (limited("l:" + ip, 8, 600e3)) return err("Too many attempts, wait 10 minutes", 429);
        const user = clip(body.username, 60), pw = String(body.password || "");
        for (const [tbl, role] of [["admins", "admin"], ["staff_users", "moderator"]]) {
          const u = await db.prepare(`SELECT * FROM ${tbl} WHERE username = ?`).bind(user).first();
          const ok = u && (await checkPw(pw, u.password));
          if (!ok) continue;
          if (ok === "legacy") await db.prepare(`UPDATE ${tbl} SET password = ? WHERE username = ?`).bind(await hashPw(pw), user).run();
          const r = u.role || role;
          return json({ token: await makeToken(env, user, r), role: r });
        }
        return err("Invalid username or password", 401);
      }

      if (path.startsWith("/api/admin/")) {
        const me = await readToken(env, request);
        if (!me) return err("Unauthorized", 401);

        if (path === "/api/admin/dashboard" && method === "GET") {
          const q = (s) => db.prepare(s).all().then((r) => r.results || []);
          const [creators, ads, products, orders, bookings, care, polls, charity, staff] = await Promise.all([
            q("SELECT * FROM creators ORDER BY id DESC"), q("SELECT * FROM ads ORDER BY id DESC"), q("SELECT * FROM products ORDER BY id DESC"),
            q("SELECT * FROM orders ORDER BY id DESC"), q("SELECT * FROM bookings ORDER BY id DESC"), q("SELECT * FROM care_cases ORDER BY id DESC"),
            q("SELECT * FROM polls ORDER BY id DESC"), q("SELECT * FROM charity_campaigns ORDER BY id DESC"),
            me.r === "moderator" ? [] : q("SELECT id, username, role FROM staff_users ORDER BY id DESC"),
          ]);
          return json({ username: me.u, role: me.r, creators, ads, products, orders, bookings, care, polls, charity_campaigns: charity, staff_users: staff });
        }
        if (path === "/api/admin/upload" && method === "POST") return saveImage(db, body);
        if (method === "POST") return adminWrite(db, path.slice("/api/admin/".length), body, me);
      }

      return err("Not Found", 404);
    } catch (e) {
      return err(e.message || "Server error", 500);
    }
  },
};
