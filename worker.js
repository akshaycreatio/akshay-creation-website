const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,x-webhook-signature,x-webhook-timestamp"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS }
  });

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Base64(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function logAudit(env, actor, role, action, details = "") {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_logs (actor, role, action, details) VALUES (?, ?, ?, ?)"
    ).bind(actor, role, action, details).run();
  } catch (_) {}
}

async function getSession(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT s.token, s.role, u.id AS user_id, u.username, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?"
  ).bind(token, now).first();
  if (!row || !row.active) return null;
  return row;
}

async function fetchSocialStats(env) {
  const now = new Date().toISOString();
  const results = {};

  if (env.YOUTUBE_API_KEY && env.YOUTUBE_CHANNEL_ID) {
    try {
      const ytRes = await fetch(
        `https://www.googleapis.com/youtube/v3/channels?part=statistics&id=${encodeURIComponent(env.YOUTUBE_CHANNEL_ID)}&key=${encodeURIComponent(env.YOUTUBE_API_KEY)}`
      );
      const ytData = await ytRes.json();
      const subs = Number(ytData?.items?.[0]?.statistics?.subscriberCount || 0);
      if (subs > 0) {
        const formatted = subs >= 1000 ? `${(subs / 1000).toFixed(1).replace(/\.0$/, "")}K+` : String(subs);
        await env.DB.prepare(
          "INSERT OR REPLACE INTO social_stats_cache (platform, count_text, raw_count, profile_url, status, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind("youtube", formatted, subs, "https://youtube.com/@akshaycreationshorts", "live_api", now).run();
      }
    } catch (_) {}
  }

  if (env.IG_ACCESS_TOKEN && env.IG_USER_ID) {
    try {
      const igRes = await fetch(
        `https://graph.facebook.com/v21.0/${encodeURIComponent(env.IG_USER_ID)}?fields=followers_count,username,account_type&access_token=${encodeURIComponent(env.IG_ACCESS_TOKEN)}`
      );
      const igData = await igRes.json();
      const followers = Number(igData?.followers_count || 0);
      if (followers > 0) {
        const formatted = followers >= 1000 ? `${(followers / 1000).toFixed(1).replace(/\.0$/, "")}K` : String(followers);
        await env.DB.prepare(
          "INSERT OR REPLACE INTO social_stats_cache (platform, count_text, raw_count, profile_url, status, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind("instagram", formatted, followers, "https://www.instagram.com/akshaycreation_offl", igData.account_type || "live_api", now).run();
      }
    } catch (_) {}
  }

  const cached = await env.DB.prepare("SELECT * FROM social_stats_cache").all();
  for (const r of cached.results || []) results[r.platform] = r;

  return {
    youtube: results.youtube || {
      platform: "youtube",
      count_text: "150K+",
      profile_url: "https://youtube.com/@akshaycreationshorts",
      status: "verified_baseline_api_pending",
      updated_at: null
    },
    instagram: results.instagram || {
      platform: "instagram",
      count_text: null,
      profile_url: "https://www.instagram.com/akshaycreation_offl",
      status: "awaiting_professional_api_token",
      updated_at: null
    }
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      // 1. One-time Owner Bootstrap
      if (path === "/api/auth/setup-owner" && request.method === "POST") {
        const body = await request.json();
        if (!env.OWNER_SETUP_KEY || body.setup_key !== env.OWNER_SETUP_KEY) {
          return json({ error: "Invalid setup key" }, 403);
        }
        const existing = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner'").first();
        if (existing) return json({ error: "Owner account already exists" }, 400);
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (username.length < 3 || password.length < 8) {
          return json({ error: "Username min 3 chars & password min 8 chars required" }, 400);
        }
        const salt = crypto.randomUUID();
        const hash = await sha256Hex(`${salt}:${password}`);
        await env.DB.prepare(
          "INSERT INTO users (username, password_hash, salt, role, active) VALUES (?, ?, ?, 'owner', 1)"
        ).bind(username, hash, salt).run();
        await logAudit(env, username, "owner", "OWNER_INITIALIZED", "Owner account created");
        return json({ ok: true, message: "Owner account created securely" });
      }

      // 2. Login
      if (path === "/api/auth/login" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        const expectedRole = body.role;
        const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!user || !user.active) return json({ error: "Invalid credentials" }, 401);
        if (expectedRole && user.role !== expectedRole) {
          return json({ error: `Account is not authorized for ${expectedRole} portal` }, 403);
        }
        const hash = await sha256Hex(`${user.salt}:${password}`);
        if (hash !== user.password_hash) return json({ error: "Invalid credentials" }, 401);
        const token = crypto.randomUUID() + "-" + crypto.randomUUID();
        const expiresAt = Math.floor(Date.now() / 1000) + 86400 * 7;
        await env.DB.prepare(
          "INSERT INTO sessions (token, user_id, role, expires_at) VALUES (?, ?, ?, ?)"
        ).bind(token, user.id, user.role, expiresAt).run();
        await logAudit(env, user.username, user.role, "LOGIN", "Dashboard login");
        return json({ ok: true, token, username: user.username, role: user.role });
      }

      if (path === "/api/auth/me" && request.method === "GET") {
        const session = await getSession(request, env);
        if (!session) return json({ authenticated: false }, 401);
        return json({ authenticated: true, username: session.username, role: session.role });
      }

      if (path === "/api/auth/logout" && request.method === "POST") {
        const session = await getSession(request, env);
        if (session) {
          await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(session.token).run();
          await logAudit(env, session.username, session.role, "LOGOUT", "Dashboard logout");
        }
        return json({ ok: true });
      }

      // 3. Public Data & Live Stats
      if (path === "/api/public/overview" && request.method === "GET") {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const ua = request.headers.get("User-Agent") || "";
        const visitorHash = await sha256Hex(`${ip}:${ua}`);
        await env.DB.prepare(
          "INSERT INTO site_visitors (visitor_hash, last_seen) VALUES (?, CURRENT_TIMESTAMP) ON CONFLICT(visitor_hash) DO UPDATE SET last_seen = CURRENT_TIMESTAMP"
        ).bind(visitorHash).run();

        const visitorsRow = await env.DB.prepare("SELECT COUNT(*) AS total FROM site_visitors").first();
        const active5mRow = await env.DB.prepare(
          "SELECT COUNT(*) AS live FROM site_visitors WHERE last_seen >= datetime('now', '-5 minutes')"
        ).first();
        const creators = await env.DB.prepare(
          "SELECT id, name, handle, platform, profile_url, bio, week_label, source FROM creator_spotlight WHERE status = 'approved' ORDER BY id DESC"
        ).all();
        const ads = await env.DB.prepare(
          "SELECT id, title, media_type, media_url, target_url, badge FROM ads_promotions WHERE active = 1 ORDER BY id DESC"
        ).all();
        const products = await env.DB.prepare(
          "SELECT id, title, category, description, price_inr, image_url FROM products WHERE active = 1 ORDER BY id DESC"
        ).all();
        const careCases = await env.DB.prepare(
          "SELECT id, case_title, public_summary, created_at FROM akshay_care WHERE status = 'published' AND consent_granted = 1 ORDER BY id DESC"
        ).all();
        const pollsRes = await env.DB.prepare("SELECT * FROM polls WHERE active = 1 ORDER BY id DESC").all();

        const polls = [];
        for (const p of pollsRes.results || []) {
          const opts = JSON.parse(p.options_json || "[]");
          const votes = await env.DB.prepare(
            "SELECT option_index, COUNT(*) AS cnt FROM poll_votes WHERE poll_id = ? GROUP BY option_index"
          ).bind(p.id).all();
          const counts = opts.map((_, idx) => {
            const found = (votes.results || []).find((v) => v.option_index === idx);
            return found ? Number(found.cnt) : 0;
          });
          const myVote = await env.DB.prepare(
            "SELECT option_index FROM poll_votes WHERE poll_id = ? AND voter_hash = ?"
          ).bind(p.id, visitorHash).first();
          polls.push({
            id: p.id,
            question: p.question,
            options: opts,
            counts,
            total_votes: counts.reduce((a, b) => a + b, 0),
            user_voted: myVote ? Number(myVote.option_index) : null
          });
        }

        const stats = await fetchSocialStats(env);
        return json({
          stats,
          analytics: {
            unique_visitors: Number(visitorsRow?.total || 0),
            active_now: Number(active5mRow?.live || 0)
          },
          creators: creators.results || [],
          ads: ads.results || [],
          products: products.results || [],
          care_cases: careCases.results || [],
          polls,
          upi_id: "akshaycreation7@naviaxis",
          upi_name: "Akshay K P"
        });
      }

      // 4. Real Poll Voting
      if (path === "/api/polls/vote" && request.method === "POST") {
        const body = await request.json();
        const pollId = Number(body.poll_id);
        const optionIndex = Number(body.option_index);
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const ua = request.headers.get("User-Agent") || "";
        const visitorHash = await sha256Hex(`${ip}:${ua}`);
        const poll = await env.DB.prepare("SELECT * FROM polls WHERE id = ? AND active = 1").bind(pollId).first();
        if (!poll) return json({ error: "Poll not found" }, 404);
        const opts = JSON.parse(poll.options_json || "[]");
        if (optionIndex < 0 || optionIndex >= opts.length) return json({ error: "Invalid option" }, 400);

        const res = await env.DB.prepare(
          "INSERT OR IGNORE INTO poll_votes (poll_id, option_index, voter_hash) VALUES (?, ?, ?)"
        ).bind(pollId, optionIndex, visitorHash).run();
        if (res.meta?.changes === 0) {
          return json({ error: "You have already voted on this poll" }, 409);
        }
        return json({ ok: true });
      }

      // 5. Public Submissions
      if (path === "/api/creators/apply" && request.method === "POST") {
        const b = await request.json();
        if (!b.name || !b.handle || !b.platform || !b.profile_url) {
          return json({ error: "All required fields must be filled" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO creator_spotlight (name, handle, platform, profile_url, bio, source, status) VALUES (?, ?, ?, ?, ?, 'application', 'pending')"
        ).bind(String(b.name).trim(), String(b.handle).trim(), b.platform, String(b.profile_url).trim(), String(b.bio || "").trim()).run();
        return json({ ok: true, message: "Application submitted for Akshay's review." });
      }

      if (path === "/api/services/book" && request.method === "POST") {
        const b = await request.json();
        if (!b.service_type || !b.client_name || !b.client_email || !b.details) {
          return json({ error: "Please fill all required booking fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO service_bookings (service_type, client_name, client_email, client_contact, details) VALUES (?, ?, ?, ?, ?)"
        ).bind(b.service_type, b.client_name, b.client_email, b.client_contact || "", b.details).run();
        return json({ ok: true, message: "Service enquiry received. Our team will reach out shortly." });
      }

      if (path === "/api/care/submit" && request.method === "POST") {
        const b = await request.json();
        if (!b.applicant_name || !b.contact_info || !b.case_title || !b.private_details) {
          return json({ error: "Please complete all required fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO akshay_care (applicant_name, contact_info, case_title, private_details, consent_granted, status) VALUES (?, ?, ?, ?, ?, 'pending_review')"
        ).bind(b.applicant_name, b.contact_info, b.case_title, b.private_details, b.consent_granted ? 1 : 0).run();
        return json({ ok: true, message: "Submitted privately to AKSHAY CARE. Nothing is published without verification & consent." });
      }

      // 6A. Direct UPI QR Checkout (akshaycreation7@naviaxis + 12-Digit UTR Submission)
      if (path === "/api/checkout/upi-submit" && request.method === "POST") {
        const b = await request.json();
        const product = await env.DB.prepare("SELECT * FROM products WHERE id = ? AND active = 1").bind(Number(b.product_id)).first();
        if (!product) return json({ error: "Product not found" }, 404);
        const name = String(b.customer_name || "").trim();
        const email = String(b.customer_email || b.buyer_email || "").trim();
        const phone = String(b.customer_phone || "0000000000").trim();
        const utr = String(b.utr || "").replace(/\s+/g, "").trim();

        if (!name || !email) {
          return json({ error: "Name and Email are required" }, 400);
        }
        if (!/^\d{12}$/.test(utr)) {
          return json({ error: "Please enter a valid 12-digit UPI UTR / Reference number" }, 400);
        }

        const dup = await env.DB.prepare("SELECT order_id FROM orders WHERE utr = ?").bind(utr).first();
        if (dup) {
          return json({ error: "This UTR number is already submitted. Check your Order ID: " + dup.order_id }, 409);
        }

        const orderId = `AKC_${Date.now()}_${Math.floor(1000 + Math.random() * 9000)}`;
        await env.DB.prepare(
          "INSERT INTO orders (order_id, product_id, customer_name, customer_email, buyer_email, customer_phone, amount_inr, utr, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_VERIFICATION')"
        ).bind(orderId, product.id, name, email, email, phone, product.price_inr, utr).run();

        return json({
          ok: true,
          order_id: orderId,
          status: "PENDING_VERIFICATION",
          product_title: product.title,
          message: "Payment UTR submitted! Akshay will verify your Navi UPI receipt and unlock your download shortly."
        });
      }

      // 6B. Cashfree Secure Checkout (Optional Backup)
      if (path === "/api/checkout/create-order" && request.method === "POST") {
        const b = await request.json();
        const product = await env.DB.prepare("SELECT * FROM products WHERE id = ? AND active = 1").bind(Number(b.product_id)).first();
        if (!product) return json({ error: "Product not found" }, 404);
        if (!b.customer_name || !b.customer_email || !b.customer_phone) {
          return json({ error: "Name, email, and phone are required for checkout" }, 400);
        }
        if (!env.CASHFREE_APP_ID || !env.CASHFREE_SECRET_KEY) {
          return json({ error: "Payment gateway credentials not configured by owner yet" }, 503);
        }
        const orderId = `AKC_${Date.now()}_${Math.floor(1000 + Math.random() * 9000)}`;
        const cfEnv = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'cashfree_env'").first();
        const baseUrl = cfEnv?.value === "PRODUCTION" ? "https://api.cashfree.com/pg" : "https://sandbox.cashfree.com/pg";

        await env.DB.prepare(
          "INSERT INTO orders (order_id, product_id, customer_name, customer_email, buyer_email, customer_phone, amount_inr, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')"
        ).bind(orderId, product.id, b.customer_name, b.customer_email, b.customer_email, b.customer_phone, product.price_inr).run();

        const cfRes = await fetch(`${baseUrl}/orders`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-version": "2023-08-01",
            "x-client-id": env.CASHFREE_APP_ID,
            "x-client-secret": env.CASHFREE_SECRET_KEY
          },
          body: JSON.stringify({
            order_id: orderId,
            order_amount: product.price_inr,
            order_currency: "INR",
            customer_details: {
              customer_id: `cust_${await sha256Hex(b.customer_email).then((h) => h.slice(0, 12))}`,
              customer_name: b.customer_name,
              customer_email: b.customer_email,
              customer_phone: b.customer_phone
            },
            order_meta: {
              return_url: `${url.origin}/?order_id={order_id}`
            }
          })
        });
        const cfData = await cfRes.json();
        if (!cfRes.ok) {
          return json({ error: cfData.message || "Gateway order creation failed" }, 502);
        }
        return json({
          ok: true,
          order_id: orderId,
          payment_session_id: cfData.payment_session_id,
          environment: cfEnv?.value === "PRODUCTION" ? "production" : "sandbox"
        });
      }

      // Server-side verification
      if (path === "/api/checkout/verify" && request.method === "GET") {
        const orderId = (url.searchParams.get("order_id") || "").trim();
        const order = await env.DB.prepare(
          "SELECT o.*, p.title AS product_title, p.download_url FROM orders o JOIN products p ON p.id = o.product_id WHERE o.order_id = ? OR o.utr = ?"
        ).bind(orderId, orderId).first();
        if (!order) return json({ error: "Order not found" }, 404);

        if (order.status !== "PAID" && !order.utr && env.CASHFREE_APP_ID && env.CASHFREE_SECRET_KEY) {
          const cfEnv = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'cashfree_env'").first();
          const baseUrl = cfEnv?.value === "PRODUCTION" ? "https://api.cashfree.com/pg" : "https://sandbox.cashfree.com/pg";
          const verifyRes = await fetch(`${baseUrl}/orders/${encodeURIComponent(order.order_id)}`, {
            headers: {
              "x-api-version": "2023-08-01",
              "x-client-id": env.CASHFREE_APP_ID,
              "x-client-secret": env.CASHFREE_SECRET_KEY
            }
          });
          const verifyData = await verifyRes.json();
          if (verifyData.order_status === "PAID") {
            await env.DB.prepare("UPDATE orders SET status = 'PAID', gateway_ref = ? WHERE order_id = ?")
              .bind(String(verifyData.cf_order_id || ""), order.order_id).run();
            order.status = "PAID";
          }
        }

        return json({
          order_id: order.order_id,
          product_title: order.product_title,
          status: order.status,
          utr: order.utr || null,
          download_url: order.status === "PAID" ? order.download_url : null
        });
      }

      // Signed Cashfree Webhook Verification
      if (path === "/api/webhooks/cashfree" && request.method === "POST") {
        const rawBody = await request.text();
        const signature = request.headers.get("x-webhook-signature") || "";
        const timestamp = request.headers.get("x-webhook-timestamp") || "";
        if (!env.CASHFREE_SECRET_KEY) return json({ error: "Not configured" }, 503);
        const expected = await hmacSha256Base64(env.CASHFREE_SECRET_KEY, timestamp + rawBody);
        if (signature !== expected) {
          return json({ error: "Invalid webhook signature" }, 401);
        }
        const event = JSON.parse(rawBody);
        const orderId = event?.data?.order?.order_id;
        const paymentStatus = event?.data?.payment?.payment_status;
        if (orderId && paymentStatus === "SUCCESS") {
          await env.DB.prepare("UPDATE orders SET status = 'PAID', gateway_ref = ? WHERE order_id = ?")
            .bind(String(event?.data?.payment?.cf_payment_id || ""), orderId).run();
        }
        return json({ ok: true });
      }

      // 7. Protected Admin & Moderator Routes
      if (path.startsWith("/api/admin/")) {
        const session = await getSession(request, env);
        if (!session) return json({ error: "Unauthorized" }, 401);
        const isOwner = session.role === "owner";

        if (path === "/api/admin/dashboard" && request.method === "GET") {
          const creators = await env.DB.prepare("SELECT * FROM creator_spotlight ORDER BY id DESC").all();
          const ads = await env.DB.prepare("SELECT * FROM ads_promotions ORDER BY id DESC").all();
          const products = await env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all();
          const orders = await env.DB.prepare(
            "SELECT o.*, p.title AS product_title FROM orders o LEFT JOIN products p ON p.id = o.product_id ORDER BY o.id DESC LIMIT 100"
          ).all();
          const bookings = await env.DB.prepare("SELECT * FROM service_bookings ORDER BY id DESC").all();
          const care = await env.DB.prepare("SELECT * FROM akshay_care ORDER BY id DESC").all();
          const polls = await env.DB.prepare("SELECT * FROM polls ORDER BY id DESC").all();
          const logs = isOwner
            ? await env.DB.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").all()
            : { results: [] };
          const moderators = isOwner
            ? await env.DB.prepare("SELECT id, username, role, active, created_at FROM users WHERE role = 'moderator'").all()
            : { results: [] };
          const settings = isOwner
            ? await env.DB.prepare("SELECT * FROM site_settings").all()
            : { results: [] };

          return json({
            role: session.role,
            username: session.username,
            creators: creators.results || [],
            ads: ads.results || [],
            products: products.results || [],
            orders: orders.results || [],
            bookings: bookings.results || [],
            care: care.results || [],
            polls: polls.results || [],
            logs: logs.results || [],
            moderators: moderators.results || [],
            settings: settings.results || []
          });
        }

        // Approve or Reject Direct UPI UTR Payment
        if (path === "/api/admin/orders/verify" && request.method === "POST") {
          const b = await request.json();
          const status = b.action === "approve" ? "PAID" : "REJECTED";
          await env.DB.prepare("UPDATE orders SET status = ?, gateway_ref = ? WHERE order_id = ?")
            .bind(status, `UPI_VERIFIED_BY_${session.username.toUpperCase()}`, String(b.order_id)).run();
          await logAudit(env, session.username, session.role, "ORDER_UTR_VERIFIED", `${b.order_id} -> ${status}`);
          return json({ ok: true, status });
        }

        if (path === "/api/admin/creators" && request.method === "POST") {
          const b = await request.json();
          if (b.action === "create") {
            await env.DB.prepare(
              "INSERT INTO creator_spotlight (name, handle, platform, profile_url, bio, week_label, source, status) VALUES (?, ?, ?, ?, ?, ?, 'selected', 'approved')"
            ).bind(b.name, b.handle, b.platform, b.profile_url, b.bio || "", b.week_label || "Featured").run();
            await logAudit(env, session.username, session.role, "CREATOR_ADDED", b.name);
          } else if (b.action === "status") {
            await env.DB.prepare("UPDATE creator_spotlight SET status = ?, week_label = COALESCE(?, week_label) WHERE id = ?")
              .bind(b.status, b.week_label || null, Number(b.id)).run();
            await logAudit(env, session.username, session.role, "CREATOR_STATUS", `#${b.id} -> ${b.status}`);
          } else if (b.action === "delete") {
            await env.DB.prepare("DELETE FROM creator_spotlight WHERE id = ?").bind(Number(b.id)).run();
            await logAudit(env, session.username, session.role, "CREATOR_DELETED", `#${b.id}`);
          }
          return json({ ok: true });
        }

        if (path === "/api/admin/ads" && request.method === "POST") {
          const b = await request.json();
          if (b.action === "create") {
            await env.DB.prepare(
              "INSERT INTO ads_promotions (title, media_type, media_url, target_url, badge, active) VALUES (?, ?, ?, ?, ?, 1)"
            ).bind(b.title, b.media_type, b.media_url, b.target_url, b.badge || "Sponsored").run();
            await logAudit(env, session.username, session.role, "AD_CREATED", b.title);
          } else if (b.action === "delete") {
            await env.DB.prepare("DELETE FROM ads_promotions WHERE id = ?").bind(Number(b.id)).run();
            await logAudit(env, session.username, session.role, "AD_DELETED", `#${b.id}`);
          }
          return json({ ok: true });
        }

        if (path === "/api/admin/products" && request.method === "POST") {
          const b = await request.json();
          if (b.action === "create") {
            await env.DB.prepare(
              "INSERT INTO products (title, category, description, price_inr, image_url, download_url, active) VALUES (?, ?, ?, ?, ?, ?, 1)"
            ).bind(b.title, b.category, b.description || "", Number(b.price_inr), String(b.image_url || "").trim(), b.download_url).run();
            await logAudit(env, session.username, session.role, "PRODUCT_CREATED", b.title);
          } else if (b.action === "delete") {
            await env.DB.prepare("UPDATE products SET active = 0 WHERE id = ?").bind(Number(b.id)).run();
            await logAudit(env, session.username, session.role, "PRODUCT_ARCHIVED", `#${b.id}`);
          }
          return json({ ok: true });
        }

        if (path === "/api/admin/bookings" && request.method === "POST") {
          const b = await request.json();
          await env.DB.prepare("UPDATE service_bookings SET status = ? WHERE id = ?")
            .bind(b.status, Number(b.id)).run();
          await logAudit(env, session.username, session.role, "BOOKING_UPDATED", `#${b.id} -> ${b.status}`);
          return json({ ok: true });
        }

        if (path === "/api/admin/care" && request.method === "POST") {
          const b = await request.json();
          if (b.status === "published" && !b.consent_granted) {
            return json({ error: "Explicit consent is mandatory before publishing AKSHAY CARE cases" }, 400);
          }
          await env.DB.prepare(
            "UPDATE akshay_care SET status = ?, public_summary = ?, consent_granted = ? WHERE id = ?"
          ).bind(b.status, b.public_summary || "", b.consent_granted ? 1 : 0, Number(b.id)).run();
          await logAudit(env, session.username, session.role, "CARE_UPDATED", `#${b.id} -> ${b.status}`);
          return json({ ok: true });
        }

        if (path === "/api/admin/polls" && request.method === "POST") {
          const b = await request.json();
          if (b.action === "create") {
            const options = (b.options || []).map((o) => String(o).trim()).filter(Boolean);
            if (!b.question || options.length < 2) return json({ error: "Question and at least 2 options required" }, 400);
            await env.DB.prepare("INSERT INTO polls (question, options_json, active) VALUES (?, ?, 1)")
              .bind(b.question, JSON.stringify(options)).run();
            await logAudit(env, session.username, session.role, "POLL_CREATED", b.question);
          } else if (b.action === "close") {
            await env.DB.prepare("UPDATE polls SET active = 0 WHERE id = ?").bind(Number(b.id)).run();
            await logAudit(env, session.username, session.role, "POLL_CLOSED", `#${b.id}`);
          }
          return json({ ok: true });
        }

        if (path.startsWith("/api/admin/owner/")) {
          if (!isOwner) return json({ error: "Owner privileges required" }, 403);

          if (path === "/api/admin/owner/moderators" && request.method === "POST") {
            const b = await request.json();
            if (b.action === "create") {
              const username = String(b.username || "").trim().toLowerCase();
              const password = String(b.password || "");
              if (username.length < 3 || password.length < 8) {
                return json({ error: "Username min 3 chars & password min 8 chars required" }, 400);
              }
              const salt = crypto.randomUUID();
              const hash = await sha256Hex(`${salt}:${password}`);
              await env.DB.prepare(
                "INSERT INTO users (username, password_hash, salt, role, active) VALUES (?, ?, ?, 'moderator', 1)"
              ).bind(username, hash, salt).run();
              await logAudit(env, session.username, "owner", "MODERATOR_CREATED", username);
            } else if (b.action === "toggle") {
              await env.DB.prepare("UPDATE users SET active = ? WHERE id = ? AND role = 'moderator'")
                .bind(b.active ? 1 : 0, Number(b.id)).run();
              await logAudit(env, session.username, "owner", "MODERATOR_TOGGLED", `#${b.id}`);
            }
            return json({ ok: true });
          }

          if (path === "/api/admin/owner/settings" && request.method === "POST") {
            const b = await request.json();
            for (const [k, v] of Object.entries(b.settings || {})) {
              await env.DB.prepare("INSERT OR REPLACE INTO site_settings (key, value) VALUES (?, ?)")
                .bind(k, String(v)).run();
            }
            await logAudit(env, session.username, "owner", "OWNER_SETTINGS_UPDATED", Object.keys(b.settings || {}).join(", "));
            return json({ ok: true });
          }
        }
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: err.message || "Server error" }, 500);
    }
  }
};
