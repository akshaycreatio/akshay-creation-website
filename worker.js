export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const jsonRes = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });

    try {
      // Public Overview API
      if (path === "/api/public/overview" && method === "GET") {
        const [creators, ads, products, polls, charity] = await Promise.all([
          env.DB.prepare("SELECT * FROM creators WHERE status = 'approved' ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC").all(),
          env.DB.prepare("SELECT * FROM products WHERE active = 1 ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM polls ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM charity_campaigns WHERE active = 1 ORDER BY id DESC LIMIT 1").first()
        ]);

        const pollsWithOptions = await Promise.all(
          (polls.results || []).map(async (p) => {
            let options = [];
            try { options = JSON.parse(p.options || "[]"); } catch (e) {}
            let counts = [];
            try { counts = JSON.parse(p.counts || "[]"); } catch (e) {}
            if (!counts.length) counts = options.map(() => 0);
            const total_votes = counts.reduce((a, b) => a + b, 0);
            return { ...p, options, counts, total_votes };
          })
        );

        return jsonRes({
          creators: creators.results || [],
          ads: ads.results || [],
          products: products.results || [],
          polls: pollsWithOptions,
          charity: charity || null
        });
      }

      // Creator Apply API
      if (path === "/api/creators/apply" && method === "POST") {
        const body = await request.json();
        if (!body.name || !body.handle || !body.profile_url) {
          return jsonRes({ error: "Missing required fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO creators (name, platform, handle, profile_url, avatar_url, bio, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')"
        ).bind(body.name, body.platform || "YouTube", body.handle, body.profile_url, body.avatar_url || "", body.bio || "").run();
        return jsonRes({ success: true });
      }

      // Services Booking API
      if (path === "/api/services/book" && method === "POST") {
        const body = await request.json();
        if (!body.client_name || !body.client_email || !body.details) {
          return jsonRes({ error: "Missing required fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO bookings (service_type, client_name, client_email, client_contact, details, status) VALUES (?, ?, ?, ?, ?, 'pending')"
        ).bind(body.service_type || "General", body.client_name, body.client_email, body.client_contact || "", body.details).run();
        return jsonRes({ success: true });
      }

      // Care Support Submit API
      if (path === "/api/care/submit" && method === "POST") {
        const body = await request.json();
        if (!body.applicant_name || !body.private_details) {
          return jsonRes({ error: "Missing required fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO care_cases (applicant_name, contact_info, case_title, private_details, consent_granted, status) VALUES (?, ?, ?, ?, ?, 'pending')"
        ).bind(body.applicant_name, body.contact_info || "", body.case_title || "Support Request", body.private_details, body.consent_granted ? 1 : 0).run();
        return jsonRes({ success: true });
      }

      // Checkout UPI Submit API (12 digit UTR validation)
      if (path === "/api/checkout/upi-submit" && method === "POST") {
        const body = await request.json();
        if (!body.product_id || !body.customer_name || !body.utr) {
          return jsonRes({ error: "Missing required fields" }, 400);
        }
        if (String(body.utr).length !== 12 || isNaN(body.utr)) {
          return jsonRes({ error: "UTR number must be exactly 12 digits" }, 400);
        }
        const orderId = "AKC_" + Math.random().toString(36).substring(2, 9).toUpperCase();
        await env.DB.prepare(
          "INSERT INTO orders (order_id, product_id, customer_name, customer_email, utr, status) VALUES (?, ?, ?, ?, ?, 'PENDING')"
        ).bind(orderId, body.product_id, body.customer_name, body.customer_email || "", body.utr).run();
        return jsonRes({ success: true, order_id: orderId });
      }

      // Checkout Verify API
      if (path === "/api/checkout/verify" && method === "GET") {
        const orderId = url.searchParams.get("order_id");
        if (!orderId) return jsonRes({ error: "Order ID or UTR required" }, 400);
        const order = await env.DB.prepare(
          "SELECT o.*, p.download_url FROM orders o LEFT JOIN products p ON o.product_id = p.id WHERE o.order_id = ? OR o.utr = ?"
        ).bind(orderId, orderId).first();
        if (!order) return jsonRes({ error: "Order not found" }, 404);
        return jsonRes({ status: order.status, download_url: order.status === "PAID" ? order.download_url : null });
      }

      // Poll Vote API
      if (path === "/api/polls/vote" && method === "POST") {
        const body = await request.json();
        const poll = await env.DB.prepare("SELECT * FROM polls WHERE id = ?").bind(body.poll_id).first();
        if (!poll) return jsonRes({ error: "Poll not found" }, 404);
        let counts = [];
        try { counts = JSON.parse(poll.counts || "[]"); } catch (e) {}
        let options = [];
        try { options = JSON.parse(poll.options || "[]"); } catch (e) {}
        if (!counts.length) counts = options.map(() => 0);
        const idx = parseInt(body.option_index);
        if (isNaN(idx) || idx < 0 || idx >= counts.length) return jsonRes({ error: "Invalid option" }, 400);
        counts[idx]++;
        await env.DB.prepare("UPDATE polls SET counts = ? WHERE id = ?").bind(JSON.stringify(counts), body.poll_id).run();
        return jsonRes({ success: true });
      }

      // Admin Login API
      if (path === "/api/auth/login" && method === "POST") {
        const body = await request.json();
        const admin = await env.DB.prepare("SELECT * FROM admins WHERE username = ? AND password = ?").bind(body.username, body.password).first();
        if (!admin) return jsonRes({ error: "Invalid username or password" }, 401);
        const token = "tok_" + Math.random().toString(36.2) + Date.now();
        return jsonRes({ token, role: admin.role || "admin" });
      }

      // Admin Dashboard API
      if (path === "/api/admin/dashboard" && method === "GET") {
        const authHeader = request.headers.get("Authorization") || "";
        if (!authHeader.startsWith("Bearer ")) return jsonRes({ error: "Unauthorized" }, 401);

        const [creators, ads, products, orders, bookings, care, polls, charity, staff] = await Promise.all([
          env.DB.prepare("SELECT * FROM creators ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM ads ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM orders ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM bookings ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM care_cases ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM polls ORDER BY id DESC").all(),
          env.DB.prepare("SELECT * FROM charity_campaigns ORDER BY id DESC").all(),
          env.DB.prepare("SELECT id, username, role FROM staff_users ORDER BY id DESC").all()
        ]);

        return jsonRes({
          username: "admin",
          role: "Super Admin",
          creators: creators.results || [],
          ads: ads.results || [],
          products: products.results || [],
          orders: orders.results || [],
          bookings: bookings.results || [],
          care: care.results || [],
          polls: polls.results || [],
          charity_campaigns: charity.results || [],
          staff_users: staff.results || []
        });
      }

      // Admin CRUD Endpoints
      if (path.startsWith("/api/admin/") && method === "POST") {
        const sub = path.replace("/api/admin/", "");
        const body = await request.json();
        const { action, id, data, status } = body;

        let table = "";
        if (sub === "creators") table = "creators";
        else if (sub === "ads") table = "ads";
        else if (sub === "charity") table = "charity_campaigns";
        else if (sub === "products") table = "products";
        else if (sub === "polls") table = "polls";
        else if (sub === "staff") table = "staff_users";
        else if (sub === "orders" || sub === "bookings" || sub === "care") table = sub === "orders" ? "orders" : sub === "bookings" ? "bookings" : "care_cases";

        if (table) {
          if (action === "delete" && id) {
            await env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
            return jsonRes({ success: true });
          }
          if (action === "status" && id && status) {
            await env.DB.prepare(`UPDATE ${table} SET status = ? WHERE id = ?`).bind(status, id).run();
            return jsonRes({ success: true });
          }
          if (action === "update" && id && data) {
            if (table === "charity_campaigns") {
              await env.DB.prepare(`UPDATE charity_campaigns SET title = ?, banner_url = ?, target_amount = ?, raised_amount = ?, upi_id = ?, upi_name = ?, donate_link = ?, description = ?, active = ? WHERE id = ?`).bind(data.title, data.banner_url, data.target_amount, data.raised_amount, data.upi_id, data.upi_name, data.donate_link, data.description, data.active, id).run();
            } else if (table === "polls") {
              await env.DB.prepare(`UPDATE polls SET question = ?, options = ? WHERE id = ?`).bind(data.question, JSON.stringify(data.options), id).run();
            }
            return jsonRes({ success: true });
          }
          if (action === "create" && data) {
            if (table === "charity_campaigns") {
              await env.DB.prepare(`INSERT INTO charity_campaigns (title, banner_url, target_amount, raised_amount, upi_id, upi_name, donate_link, description, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(data.title, data.banner_url || "", data.target_amount || 0, data.raised_amount || 0, data.upi_id || "", data.upi_name || "", data.donate_link || "", data.description || "", data.active || 1).run();
            } else if (table === "polls") {
              await env.DB.prepare(`INSERT INTO polls (question, options, counts) VALUES (?, ?, ?)`).bind(data.question, JSON.stringify(data.options), JSON.stringify(data.options.map(() => 0))).run();
            } else if (table === "staff_users") {
              await env.DB.prepare(`INSERT INTO staff_users (username, password, role) VALUES (?, ?, ?)`).bind(data.username, data.password, data.role || "moderator").run();
            }
            return jsonRes({ success: true });
          }
        }
      }

      return jsonRes({ error: "Not Found" }, 404);
    } catch (err) {
      return jsonRes({ error: err.message }, 500);
    }
  },
};
