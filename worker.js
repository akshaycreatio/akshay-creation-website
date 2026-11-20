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

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });

const safeJson = (str, fallback) => {
  try {
    const parsed = JSON.parse(str);
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
};

const getDb = (env) => env.DB || env.akshay_creation_db || env.AKSHAY_CREATION_DB;

async function handlePublicOverview(env) {
  const db = getDb(env);
  if (!db) {
    return json({ error: "D1 database binding not found" }, 500);
  }

  const [creatorsRes, adsRes, charitiesRes, productsRes, pollsRes] = await Promise.allSettled([
    db.prepare("SELECT * FROM creators WHERE status = 'approved' ORDER BY id DESC").all(),
    db.prepare("SELECT * FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC").all(),
    db.prepare("SELECT * FROM charity_campaigns WHERE active = 1 ORDER BY id DESC").all(),
    db.prepare("SELECT id, title, category, description, price_inr, image_url FROM products WHERE active = 1 ORDER BY id DESC").all(),
    db.prepare("SELECT * FROM polls WHERE active = 1 ORDER BY id DESC").all(),
  ]);

  const creators = creatorsRes.status === "fulfilled" ? creatorsRes.value?.results || [] : [];
  const ads = adsRes.status === "fulfilled" ? adsRes.value?.results || [] : [];
  const charities = charitiesRes.status === "fulfilled" ? charitiesRes.value?.results || [] : [];
  const products = productsRes.status === "fulfilled" ? productsRes.value?.results || [] : [];
  const pollsRows = pollsRes.status === "fulfilled" ? pollsRes.value?.results || [] : [];

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

  return json({
    creators,
    ads,
    charities,
    products,
    polls,
  });
}

async function handleAdminPolls(request, env) {
  const db = getDb(env);
  if (!db) {
    return json({ error: "D1 database binding not found" }, 500);
  }

  const body = await request.json().catch(() => null);
  if (!body || !body.action) {
    return json({ error: "Invalid request body" }, 400);
  }

  if (body.action === "create") {
    const question = String(body.data?.question || "").trim();
    const options = Array.isArray(body.data?.options)
      ? body.data.options.map((s) => String(s).trim()).filter(Boolean)
      : [];
    const priorityIndex = Math.max(
      0,
      Number.isFinite(+body.data?.priority_index) ? Math.floor(+body.data.priority_index) : 0
    );
    const durationHours = Math.max(
      1,
      Number.isFinite(+body.data?.duration_hours) ? +body.data.duration_hours : 48
    );
    const createdAt = new Date().toISOString();

    if (!question || options.length < 2) {
      return json({ error: "Question and at least 2 options required" }, 400);
    }

    const counts = options.map(() => 0);

    await db
      .prepare(
        `INSERT INTO polls (question, options_json, counts_json, priority_index, duration_hours, active, created_at)
         VALUES (?, ?, ?, ?, ?, 1, ?)`
      )
      .bind(
        question,
        JSON.stringify(options),
        JSON.stringify(counts),
        priorityIndex,
        durationHours,
        createdAt
      )
      .run();

    return json({ ok: true });
  }

  if (body.action === "update") {
    const id = +body.id;
    const d = body.data || {};
    const updates = [];
    const binds = [];

    if (!Number.isFinite(id) || id <= 0) {
      return json({ error: "Valid poll id required" }, 400);
    }

    if (d.question !== undefined) {
      updates.push("question = ?");
      binds.push(String(d.question).trim());
    }
    if (Array.isArray(d.options) && d.options.length >= 2) {
      updates.push("options_json = ?");
      binds.push(JSON.stringify(d.options));
    }
    if (d.priority_index !== undefined && d.priority_index !== "") {
      updates.push("priority_index = ?");
      binds.push(Math.max(0, Math.floor(+d.priority_index)));
    }
    if (d.duration_hours !== undefined && d.duration_hours !== "") {
      updates.push("duration_hours = ?");
      binds.push(Math.max(1, +d.duration_hours));
    }
    if (d.active !== undefined) {
      updates.push("active = ?");
      binds.push(+d.active ? 1 : 0);
    }

    if (!updates.length) return json({ ok: true });
    binds.push(id);

    await db.prepare(`UPDATE polls SET ${updates.join(", ")} WHERE id = ?`).bind(...binds).run();
    return json({ ok: true });
  }

  if (body.action === "delete") {
    const id = +body.id;
    if (!Number.isFinite(id) || id <= 0) {
      return json({ error: "Valid poll id required" }, 400);
    }
    await db.prepare("DELETE FROM polls WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  return json({ error: "Unsupported action" }, 400);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    if (pathname === "/api/public/overview" && request.method === "GET") {
      return handlePublicOverview(env);
    }

    if (pathname === "/api/admin/polls" && request.method === "POST") {
      return handleAdminPolls(request, env);
    }

    if (pathname === "/api/utils/validate-youtube" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      return json({ valid_url: youtubeLink(body.url) });
    }

    if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};
