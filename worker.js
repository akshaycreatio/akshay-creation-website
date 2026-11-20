const youtubeLink = (u) => {
  try {
    const x = new URL(String(u || ""));
    if (x.protocol !== "https:") return "";
    const host = x.hostname.toLowerCase().replace(/^www\./, "");
    let id = "";

    if (host === "youtu.be") {
      id = x.pathname.slice(1).split("/")[0];
    } else if (host === "youtube.com" || host === "m.youtube.com") {
      id = (x.pathname.match(/^\/(?:live|embed|shorts)\/([^/?]+)/) || [])[1] || x.searchParams.get("v") || "";
    }

    return /^[\w-]{11}$/.test(id) ? x.toString().slice(0, 1000) : "";
  } catch {
    return "";
  }
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...CORS,
      ...extraHeaders,
    },
  });

const safeJson = (str, fallback) => {
  try {
    if (Array.isArray(str) || (typeof str === "object" && str !== null)) return str;
    const parsed = JSON.parse(str);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
};

const getDb = (env) => env.DB || env.akshay_creation_db || env.AKSHAY_CREATION_DB;

async function sha256Hex(text) {
  const buf = new TextEncoder().encode(String(text));
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function signPayload(payloadObj, secret) {
  const payload = btoa(unescape(encodeURIComponent(JSON.stringify(payloadObj))));
  const sig = (await sha256Hex(`${payload}.${secret || "akc_default_secret"}`)).slice(0, 32);
  return `${payload}.${sig}`;
}

async function verifyToken(authHeader, secret) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const raw = authHeader.slice(7).trim();
  const [payload, sig] = raw.split(".");
  if (!payload || !sig) return null;
  const expected = (await sha256Hex(`${payload}.${secret || "akc_default_secret"}`)).slice(0, 32);
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(decodeURIComponent(escape(atob(payload))));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady || !db) return;
  const stmts = [
    `CREATE TABLE IF NOT EXISTS creators (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, platform TEXT, handle TEXT, profile_url TEXT, avatar_url TEXT, bio TEXT,
      status TEXT DEFAULT 'pending', created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS ads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, badge TEXT, media_url TEXT, target_url TEXT, sort INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1, created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS charity_campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, banner_url TEXT, target_amount REAL DEFAULT 0, raised_amount REAL DEFAULT 0,
      upi_id TEXT, upi_name TEXT, donate_link TEXT, description TEXT,
      active INTEGER DEFAULT 1, created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, category TEXT, description TEXT, price_inr REAL DEFAULT 0,
      image_url TEXT, download_url TEXT, active INTEGER DEFAULT 1, created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id TEXT UNIQUE, product_id INTEGER, product_title TEXT, amount_inr REAL,
      customer_name TEXT, customer_email TEXT, utr TEXT, status TEXT DEFAULT 'PENDING', created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      service_type TEXT, client_name TEXT, client_email TEXT, client_contact TEXT, details TEXT,
      status TEXT DEFAULT 'new', created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS care (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      applicant_name TEXT, contact_info TEXT, case_title TEXT, private_details TEXT,
      consent_granted INTEGER DEFAULT 1, status TEXT DEFAULT 'new', created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS polls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      question TEXT, options_json TEXT, counts_json TEXT,
      priority_index INTEGER DEFAULT 0, duration_hours REAL DEFAULT 48,
      active INTEGER DEFAULT 1, created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS staff_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'moderator', created_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS live_stream (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      title TEXT, youtube_url TEXT, active INTEGER DEFAULT 0, updated_at TEXT
    )`,
  ];

  for (const sql of stmts) {
    await db.prepare(sql).run().catch(() => {});
  }
  await db.prepare("ALTER TABLE polls ADD COLUMN priority_index INTEGER DEFAULT 0").run().catch(() => {});
  await db.prepare("ALTER TABLE polls ADD COLUMN duration_hours REAL DEFAULT 48").run().catch(() => {});
  await db.prepare("ALTER TABLE polls ADD COLUMN created_at TEXT").run().catch(() => {});
  schemaReady = true;
}

/* ---------- Auth & Dashboard ---------- */
async function handleLogin(request, env) {
  const db = getDb(env);
  await ensureSchema(db);
  const body = await request.json().catch(() => null);
  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");

  if (!username || !password) {
    return json({ error: "Username and password required" }, 400);
  }

  const ownerKey = env.OWNER_SETUP_KEY || env.ADMIN_PASSWORD || "";
  const ownerUser = env.ADMIN_USERNAME || "OWNER_SETUP_KEY";

  if (ownerKey && (username === "OWNER_SETUP_KEY" || username === ownerUser) && password === ownerKey) {
    const token = await signPayload(
      { username: "Akshay (Owner)", role: "admin", exp: Date.now() + 7 * 86400 * 1000 },
      env.JWT_SECRET || ownerKey
    );
    return json({ token, username: "Akshay (Owner)", role: "admin" });
  }

  if (db) {
    const passHash = await sha256Hex(password);
    const staff = await db
      .prepare("SELECT id, username, role, password_hash FROM staff_users WHERE username = ?")
      .bind(username)
      .first()
      .catch(() => null);

    if (staff && (staff.password_hash === passHash || staff.password_hash === password)) {
      const token = await signPayload(
        { username: staff.username, role: staff.role || "moderator", exp: Date.now() + 7 * 86400 * 1000 },
        env.JWT_SECRET || ownerKey
      );
      return json({ token, username: staff.username, role: staff.role || "moderator" });
    }
  }

  return json({ error: "Invalid username or password" }, 401);
}

async function requireAuth(request, env) {
  const ownerKey = env.OWNER_SETUP_KEY || env.ADMIN_PASSWORD || "";
  return verifyToken(request.headers.get("Authorization"), env.JWT_SECRET || ownerKey);
}

async function handleDashboard(request, env) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);

  const db = getDb(env);
  if (!db) return json({ error: "D1 database binding not found" }, 500);
  await ensureSchema(db);

  const all = async (sql) => {
    try {
      const r = await db.prepare(sql).all();
      return r?.results || [];
    } catch {
      return [];
    }
  };

  const [creators, ads, charity_campaigns, products, orders, bookings, care, pollsRows, staff_users] =
    await Promise.all([
      all("SELECT * FROM creators ORDER BY id DESC"),
      all("SELECT * FROM ads ORDER BY sort ASC, id DESC"),
      all("SELECT * FROM charity_campaigns ORDER BY id DESC"),
      all("SELECT * FROM products ORDER BY id DESC"),
      all("SELECT * FROM orders ORDER BY id DESC"),
      all("SELECT * FROM bookings ORDER BY id DESC"),
      all("SELECT * FROM care ORDER BY id DESC"),
      all("SELECT * FROM polls ORDER BY id DESC"),
      all("SELECT id, username, role, created_at FROM staff_users ORDER BY id DESC"),
    ]);

  const polls = pollsRows.map((row) => {
    const options = safeJson(row.options_json, []);
    const counts = safeJson(row.counts_json, options.map(() => 0));
    const realTotal = counts.reduce((s, n) => s + (+n || 0), 0);
    return {
      ...row,
      options,
      counts,
      real_votes_breakdown: options.map((opt, idx) => `${opt}: ${counts[idx] || 0}`).join(" | "),
      real_total_votes: realTotal,
      priority_index: Number.isFinite(+row.priority_index) ? +row.priority_index : 0,
      duration_hours: Number.isFinite(+row.duration_hours) && +row.duration_hours > 0 ? +row.duration_hours : 48,
    };
  });

  return json({
    username: user.username,
    role: user.role,
    creators,
    ads,
    charity_campaigns,
    products,
    orders,
    bookings,
    care,
    polls,
    staff_users,
  });
}

/* ---------- Public Endpoints ---------- */
async function handlePublicOverview(env) {
  const db = getDb(env);
  if (!db) return json({ error: "D1 database binding not found" }, 500);
  await ensureSchema(db);

  const all = async (sql) => {
    try {
      const r = await db.prepare(sql).all();
      return r?.results || [];
    } catch {
      return [];
    }
  };

  const [creators, ads, charities, products, pollsRows] = await Promise.all([
    all("SELECT * FROM creators WHERE status = 'approved' ORDER BY id DESC"),
    all("SELECT * FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC"),
    all("SELECT * FROM charity_campaigns WHERE active = 1 ORDER BY id DESC"),
    all("SELECT id, title, category, description, price_inr, image_url FROM products WHERE active = 1 ORDER BY id DESC"),
    all("SELECT * FROM polls WHERE active = 1 ORDER BY id DESC"),
  ]);

  const polls = pollsRows.map((row) => {
    const options = safeJson(row.options_json, []);
    const counts = safeJson(row.counts_json, options.map(() => 0));
    const total_votes = counts.reduce((sum, n) => sum + (+n || 0), 0);

    return {
      id: row.id,
      question: row.question,
      options,
      counts,
      total_votes,
      priority_index: Number.isFinite(+row.priority_index) ? Math.max(0, Math.floor(+row.priority_index)) : 0,
      duration_hours: Number.isFinite(+row.duration_hours) && +row.duration_hours > 0 ? +row.duration_hours : 48,
      created_at: row.created_at || new Date().toISOString(),
      user_voted: null,
    };
  });

  return json({ creators, ads, charities, products, polls });
}

async function handlePollVote(request, env) {
  const db = getDb(env);
  if (!db) return json({ ok: true });
  await ensureSchema(db);

  const body = await request.json().catch(() => null);
  const pollId = +body?.poll_id;
  const optIdx = +body?.option_index;
  if (!Number.isFinite(pollId) || !Number.isFinite(optIdx) || optIdx < 0) {
    return json({ error: "Invalid vote" }, 400);
  }

  const row = await db.prepare("SELECT id, options_json, counts_json FROM polls WHERE id = ?").bind(pollId).first().catch(() => null);
  if (row) {
    const options = safeJson(row.options_json, []);
    const counts = safeJson(row.counts_json, options.map(() => 0));
    while (counts.length < options.length) counts.push(0);
    if (optIdx < counts.length) {
      counts[optIdx] = (+counts[optIdx] || 0) + 1;
      await db.prepare("UPDATE polls SET counts_json = ? WHERE id = ?").bind(JSON.stringify(counts), pollId).run().catch(() => {});
    }
  }
  return json({ ok: true });
}

/* ---------- Generic Admin Resource Handler ---------- */
const TABLE_MAP = {
  creators: { table: "creators", cols: ["name", "platform", "handle", "profile_url", "avatar_url", "bio", "status"] },
  ads: { table: "ads", cols: ["title", "badge", "media_url", "target_url", "sort", "active"] },
  charity: { table: "charity_campaigns", cols: ["title", "banner_url", "target_amount", "raised_amount", "upi_id", "upi_name", "donate_link", "description", "active"] },
  products: { table: "products", cols: ["title", "category", "description", "price_inr", "image_url", "download_url", "active"] },
  orders: { table: "orders", cols: ["status"] },
  bookings: { table: "bookings", cols: ["status"] },
  care: { table: "care", cols: ["status"] },
};

async function handleAdminResource(resName, request, env) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);

  const db = getDb(env);
  if (!db) return json({ error: "D1 database binding not found" }, 500);
  await ensureSchema(db);

  const body = await request.json().catch(() => null);
  if (!body || !body.action) return json({ error: "Invalid request" }, 400);

  if (resName === "staff") {
    if (body.action === "create") {
      const u = String(body.data?.username || "").trim();
      const p = String(body.data?.password || "");
      const role = body.data?.role === "admin" ? "admin" : "moderator";
      if (!u || p.length < 8) return json({ error: "Username and 8+ char password required" }, 400);
      const hash = await sha256Hex(p);
      await db
        .prepare("INSERT INTO staff_users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)")
        .bind(u, hash, role, new Date().toISOString())
        .run();
      return json({ ok: true });
    }
    if (body.action === "delete") {
      await db.prepare("DELETE FROM staff_users WHERE id = ?").bind(+body.id).run();
      return json({ ok: true });
    }
    return json({ error: "Unsupported staff action" }, 400);
  }

  if (resName === "polls") {
    if (body.action === "create") {
      const question = String(body.data?.question || "").trim();
      const options = Array.isArray(body.data?.options)
        ? body.data.options.map((s) => String(s).trim()).filter(Boolean)
        : [];
      const priorityIndex = Math.max(0, Number.isFinite(+body.data?.priority_index) ? Math.floor(+body.data.priority_index) : 0);
      const durationHours = Math.max(1, Number.isFinite(+body.data?.duration_hours) ? +body.data.duration_hours : 48);
      if (!question || options.length < 2) return json({ error: "Question and at least 2 options required" }, 400);
      const counts = options.map(() => 0);
      await db
        .prepare(
          `INSERT INTO polls (question, options_json, counts_json, priority_index, duration_hours, active, created_at)
           VALUES (?, ?, ?, ?, ?, 1, ?)`
        )
        .bind(question, JSON.stringify(options), JSON.stringify(counts), priorityIndex, durationHours, new Date().toISOString())
        .run();
      return json({ ok: true });
    }
    if (body.action === "update") {
      const id = +body.id;
      const d = body.data || {};
      const updates = [];
      const binds = [];
      if (d.question !== undefined) { updates.push("question = ?"); binds.push(String(d.question).trim()); }
      if (Array.isArray(d.options) && d.options.length >= 2) { updates.push("options_json = ?"); binds.push(JSON.stringify(d.options)); }
      if (d.priority_index !== undefined && d.priority_index !== "") { updates.push("priority_index = ?"); binds.push(Math.max(0, Math.floor(+d.priority_index))); }
      if (d.duration_hours !== undefined && d.duration_hours !== "") { updates.push("duration_hours = ?"); binds.push(Math.max(1, +d.duration_hours)); }
      if (d.active !== undefined) { updates.push("active = ?"); binds.push(+d.active ? 1 : 0); }
      if (!updates.length) return json({ ok: true });
      binds.push(id);
      await db.prepare(`UPDATE polls SET ${updates.join(", ")} WHERE id = ?`).bind(...binds).run();
      return json({ ok: true });
    }
    if (body.action === "delete") {
      await db.prepare("DELETE FROM polls WHERE id = ?").bind(+body.id).run();
      return json({ ok: true });
    }
  }

  const meta = TABLE_MAP[resName];
  if (!meta) return json({ error: "Unknown resource" }, 404);

  if (body.action === "delete") {
    await db.prepare(`DELETE FROM ${meta.table} WHERE id = ?`).bind(+body.id).run();
    return json({ ok: true });
  }

  if (body.action === "status") {
    await db.prepare(`UPDATE ${meta.table} SET status = ? WHERE id = ?`).bind(String(body.status || ""), +body.id).run();
    return json({ ok: true });
  }

  if (body.action === "create") {
    const d = body.data || {};
    if (resName === "creators" && !d.status) d.status = "approved";
    const cols = meta.cols.filter((c) => d[c] !== undefined && d[c] !== "");
    const vals = cols.map((c) => d[c]);
    cols.push("created_at");
    vals.push(new Date().toISOString());
    await db
      .prepare(`INSERT INTO ${meta.table} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`)
      .bind(...vals)
      .run();
    return json({ ok: true });
  }

  if (body.action === "update") {
    const d = body.data || {};
    const cols = meta.cols.filter((c) => d[c] !== undefined);
    if (!cols.length) return json({ ok: true });
    const vals = cols.map((c) => d[c]);
    vals.push(+body.id);
    await db
      .prepare(`UPDATE ${meta.table} SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ?`)
      .bind(...vals)
      .run();
    return json({ ok: true });
  }

  return json({ error: "Unsupported action" }, 400);
}

/* ---------- Live Stream Endpoints ---------- */
async function handleLiveGet(env) {
  const db = getDb(env);
  if (!db) return json({ live: null });
  await ensureSchema(db);
  const row = await db.prepare("SELECT title, youtube_url, active FROM live_stream WHERE id = 1").first().catch(() => null);
  if (!row || !+row.active) return json({ live: null });
  return json({ live: row });
}

async function handleLiveAdmin(request, env) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const db = getDb(env);
  if (!db) return json({ error: "D1 database binding not found" }, 500);
  await ensureSchema(db);

  if (request.method === "GET") {
    const row = await db.prepare("SELECT title, youtube_url, active FROM live_stream WHERE id = 1").first().catch(() => null);
    return json({ live: row || { title: "", youtube_url: "", active: 0 } });
  }

  const body = await request.json().catch(() => ({}));
  const active = body.active ? 1 : 0;
  const title = String(body.title || "").trim();
  const cleanUrl = youtubeLink(body.youtube_url);
  if (active && !cleanUrl) return json({ error: "Valid YouTube link required" }, 400);

  await db
    .prepare(
      `INSERT INTO live_stream (id, title, youtube_url, active, updated_at)
       VALUES (1, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET title = excluded.title, youtube_url = excluded.youtube_url, active = excluded.active, updated_at = excluded.updated_at`
    )
    .bind(title, cleanUrl || String(body.youtube_url || "").trim(), active, new Date().toISOString())
    .run();

  return json({ ok: true });
}

/* ---------- Main Router ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      if (pathname === "/api/auth/login" && request.method === "POST") return handleLogin(request, env);
      if (pathname === "/api/admin/dashboard" && request.method === "GET") return handleDashboard(request, env);
      if (pathname === "/api/admin/live-set") return handleLiveAdmin(request, env);
      if (pathname === "/api/admin/upload" && request.method === "POST") {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const body = await request.json().catch(() => ({}));
        if (!body.data) return json({ error: "No image data" }, 400);
        return json({ url: String(body.data) });
      }
      if (pathname.startsWith("/api/admin/") && request.method === "POST") {
        const resName = pathname.slice("/api/admin/".length);
        return handleAdminResource(resName, request, env);
      }

      if (pathname === "/api/public/overview" && request.method === "GET") return handlePublicOverview(env);
      if (pathname === "/api/public/presence" && request.method === "POST") return json({ ok: true });
      if (pathname === "/api/public/live" && request.method === "GET") return handleLiveGet(env);
      if (pathname === "/api/polls/vote" && request.method === "POST") return handlePollVote(request, env);

      if (pathname === "/api/creators/apply" && request.method === "POST") {
        const db = getDb(env);
        await ensureSchema(db);
        const d = await request.json().catch(() => ({}));
        await db
          .prepare("INSERT INTO creators (name, platform, handle, profile_url, avatar_url, bio, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)")
          .bind(d.name || "", d.platform || "", d.handle || "", d.profile_url || "", d.avatar_url || "", d.bio || "", new Date().toISOString())
          .run();
        return json({ ok: true });
      }

      if (pathname === "/api/services/book" && request.method === "POST") {
        const db = getDb(env);
        await ensureSchema(db);
        const d = await request.json().catch(() => ({}));
        await db
          .prepare("INSERT INTO bookings (service_type, client_name, client_email, client_contact, details, status, created_at) VALUES (?, ?, ?, ?, ?, 'new', ?)")
          .bind(d.service_type || "", d.client_name || "", d.client_email || "", d.client_contact || "", d.details || "", new Date().toISOString())
          .run();
        return json({ ok: true });
      }

      if (pathname === "/api/care/submit" && request.method === "POST") {
        const db = getDb(env);
        await ensureSchema(db);
        const d = await request.json().catch(() => ({}));
        await db
          .prepare("INSERT INTO care (applicant_name, contact_info, case_title, private_details, consent_granted, status, created_at) VALUES (?, ?, ?, ?, 1, 'new', ?)")
          .bind(d.applicant_name || "", d.contact_info || "", d.case_title || "", d.private_details || "", new Date().toISOString())
          .run();
        return json({ ok: true });
      }

      if (pathname === "/api/checkout/upi-submit" && request.method === "POST") {
        const db = getDb(env);
        await ensureSchema(db);
        const d = await request.json().catch(() => ({}));
        const prod = await db.prepare("SELECT title, price_inr FROM products WHERE id = ?").bind(+d.product_id).first().catch(() => null);
        const orderId = "AKC_" + Date.now().toString(36).toUpperCase();
        await db
          .prepare("INSERT INTO orders (order_id, product_id, product_title, amount_inr, customer_name, customer_email, utr, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)")
          .bind(orderId, +d.product_id || 0, prod?.title || "", prod?.price_inr || 0, d.customer_name || "", d.customer_email || "", d.utr || "", new Date().toISOString())
          .run();
        return json({ ok: true, order_id: orderId });
      }

      if (pathname === "/api/checkout/verify" && request.method === "GET") {
        const db = getDb(env);
        await ensureSchema(db);
        const q = String(url.searchParams.get("order_id") || "").trim();
        const ord = await db
          .prepare("SELECT o.status, p.download_url FROM orders o LEFT JOIN products p ON o.product_id = p.id WHERE o.order_id = ? OR o.utr = ? ORDER BY o.id DESC LIMIT 1")
          .bind(q, q)
          .first()
          .catch(() => null);
        if (!ord) return json({ status: "PENDING" });
        return json({ status: ord.status || "PENDING", download_url: ord.status === "PAID" ? ord.download_url || "#" : "" });
      }

      if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
        return env.ASSETS.fetch(request);
      }

      return new Response("Not found", { status: 404 });
    } catch (err) {
      return json({ error: err?.message || "Server error" }, 500);
    }
  },
};
