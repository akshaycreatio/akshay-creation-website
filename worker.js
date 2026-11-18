// AKSHAY CREATION backend: Cloudflare Worker + D1. Server-side logic for authentication, donations, products, & database operations.
const enc = new TextEncoder();
const j = (d, s = 200) => new Response(JSON.stringify(d), {status: s, headers: {"Content-Type": "application/json", ...CORS}});
const auth = (req, env) => {
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.substring(7).trim() : "";
  if (!token) throw new Error("Unauthorized");
  return token;
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-webhook-signature, x-webhook-timestamp",
};

async function sha256Hex(msg) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(msg));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function logAudit(env, actor, role, action, details = "") {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_logs (actor, role, action, details) VALUES (?, ?, ?, ?)"
    ).bind(actor, role, action, details).run();
  } catch (e) {}
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "POST" && path === "/api/auth/login") {
        const body = await request.json();
        const { username, password } = body;
        
        if (username === "OWNER_SETUP_KEY" && password === "AKSHAY2007ADMIN") {
          const token = await sha256Hex(username + Math.random() + Date.now());
          try {
            await env.DB.prepare(
              "UPDATE admins SET token = ?, token_created_at = ? WHERE id = 1"
            ).bind(token, Math.floor(Date.now() / 1000)).run();
          } catch(e) {}
          await logAudit(env, username, "superadmin", "ADMIN_LOGIN", "Successful superadmin login");
          return j({ token, username: "OWNER_SETUP_KEY", role: "superadmin" });
        }

        const staff = await env.DB.prepare(
          "SELECT * FROM staff_users WHERE username = ? AND password = ?"
        ).bind(username, password).first();

        if (!staff) return j({ error: "Invalid username or password" }, 401);

        const token = await sha256Hex(username + Math.random() + Date.now());
        await env.DB.prepare(
          "UPDATE staff_users SET token = ?, token_created_at = ? WHERE id = ?"
        ).bind(token, Math.floor(Date.now() / 1000), staff.id).run();

        await logAudit(env, username, staff.role, "STAFF_LOGIN", "Successful staff login");
        return j({ token, username: staff.username, role: staff.role });
      }

      if (request.method === "GET" && path === "/api/public/overview") {
        const creators = await env.DB.prepare("SELECT * FROM creators WHERE status = 'approved' ORDER BY id DESC").all();
        const ads = await env.DB.prepare("SELECT * FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC").all();
        const products = await env.DB.prepare("SELECT * FROM products WHERE active = 1 ORDER BY id DESC").all();
        const polls = await env.DB.prepare("SELECT * FROM polls WHERE active = 1 ORDER BY id DESC").all();
        
        let charity = null;
        try {
          charity = await env.DB.prepare("SELECT * FROM charity_campaigns WHERE active = 1 ORDER BY id DESC LIMIT 1").first();
        } catch(e) {}

        const pollsWithOpts = await Promise.all(polls.results.map(async (p) => {
          let opts = [];
          try { opts = JSON.parse(p.options_json); } catch(e){}
          let counts = [];
          try { counts = JSON.parse(p.counts_json); } catch(e){}
          return { ...p, options: opts, counts };
        }));

        return j({
          creators: creators.results,
          ads: ads.results,
          products: products.results,
          polls: pollsWithOpts,
          charity: charity || null
        });
      }

      if (request.method === "POST" && path === "/api/creators/apply") {
        const b = await request.json();
        if (!b.name || !b.platform || !b.handle || !b.profile_url || !b.bio) {
          return j({ error: "Missing required fields" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO creators (name, platform, handle, profile_url, avatar_url, bio, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')"
        ).bind(b.name, b.platform, b.handle, b.profile_url, b.avatar_url || "", b.bio).run();
        return j({ success: true, message: "Application submitted for review!" });
      }

      if (request.method === "POST" && path === "/api/services/book") {
        const b = await request.json();
        if (!b.service_type || !b.client_name || !b.client_email || !b.details) {
          return j({ error: "Missing required booking details" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO bookings (service_type, client_name, client_email, client_contact, details, status) VALUES (?, ?, ?, ?, ?, 'pending')"
        ).bind(b.service_type, b.client_name, b.client_email, b.client_contact || "", b.details).run();
        return j({ success: true, message: "Booking request received successfully!" });
      }

      if (request.method === "POST" && path === "/api/care/submit") {
        const b = await request.json();
        if (!b.applicant_name || !b.contact_info || !b.case_title || !b.private_details) {
          return j({ error: "Missing required care details" }, 400);
        }
        await env.DB.prepare(
          "INSERT INTO care_cases (applicant_name, contact_info, case_title, private_details, status) VALUES (?, ?, ?, ?, 'received')"
        ).bind(b.applicant_name, b.contact_info, b.case_title, b.private_details).run();
        return j({ success: true, message: "Submitted privately & securely!" });
      }

      if (request.method === "POST" && path === "/api/checkout/upi-submit") {
        const b = await request.json();
        if (!b.product_id || !b.customer_name || !b.customer_email || !b.utr) {
          return j({ error: "Missing payment confirmation details" }, 400);
        }
        if (b.utr.length !== 12 || !/^\d{12}$/.test(b.utr)) {
          return j({ error: "UTR number must be exactly 12 digits" }, 400);
        }
        const orderId = "AKC_" + Math.random().toString(36).substring(2, 9).toUpperCase();
        await env.DB.prepare(
          "INSERT INTO orders (order_id, product_id, customer_name, customer_email, utr, status) VALUES (?, ?, ?, ?, ?, 'PENDING')"
        ).bind(orderId, b.product_id, b.customer_name, b.customer_email, b.utr).run();
        return j({ success: true, order_id: orderId });
      }

      if (request.method === "GET" && path === "/api/checkout/verify") {
        const orderId = url.searchParams.get("order_id");
        if (!orderId) return j({ error: "Order ID required" }, 400);
        const order = await env.DB.prepare("SELECT * FROM orders WHERE order_id = ?").bind(orderId).first();
        if (!order) return j({ error: "Order not found" }, 404);

        let downloadUrl = "";
        if (order.status === "PAID") {
          const prod = await env.DB.prepare("SELECT download_url FROM products WHERE id = ?").bind(order.product_id).first();
          downloadUrl = prod ? prod.download_url : "";
        }
        return j({ status: order.status, download_url: downloadUrl });
      }

      if (request.method === "POST" && path === "/api/polls/vote") {
        const b = await request.json();
        const pollId = b.poll_id;
        const optIdx = parseInt(b.option_index, 10);
        if (pollId == null || isNaN(optIdx)) return j({ error: "Invalid vote parameters" }, 400);

        const poll = await env.DB.prepare("SELECT * FROM polls WHERE id = ?").bind(pollId).first();
        if (!poll) return j({ error: "Poll not found" }, 404);

        let counts = [];
        try { counts = JSON.parse(poll.counts_json); } catch(e){}
        while(counts.length <= optIdx) counts.push(0);
        counts[optIdx] = (counts[optIdx] || 0) + 1;
        const newTotal = (poll.total_votes || 0) + 1;

        await env.DB.prepare("UPDATE polls SET counts_json = ?, total_votes = ? WHERE id = ?")
          .bind(JSON.stringify(counts), newTotal, pollId).run();
        return j({ success: true });
      }

      // Admin Endpoints
      if (path.startsWith("/api/admin/")) {
        const token = auth(request, env);
        
        let admin = await env.DB.prepare("SELECT * FROM admins WHERE token = ?").bind(token).first();
        let isStaff = false;
        if (!admin) {
          admin = await env.DB.prepare("SELECT * FROM staff_users WHERE token = ?").bind(token).first();
          isStaff = true;
        }
        if (!admin) return j({ error: "Unauthorized session" }, 401);

        if (request.method === "GET" && path === "/api/admin/dashboard") {
          const creators = await env.DB.prepare("SELECT * FROM creators ORDER BY id DESC").all();
          const ads = await env.DB.prepare("SELECT * FROM ads ORDER BY sort ASC, id DESC").all();
          const products = await env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all();
          const orders = await env.DB.prepare("SELECT * FROM orders ORDER BY id DESC").all();
          const bookings = await env.DB.prepare("SELECT * FROM bookings ORDER BY id DESC").all();
          const careCases = await env.DB.prepare("SELECT * FROM care_cases ORDER BY id DESC").all();
          const polls = await env.DB.prepare("SELECT * FROM polls ORDER BY id DESC").all();
          const auditLogs = await env.DB.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50").all();
          const staffUsers = !isStaff ? await env.DB.prepare("SELECT id, username, role FROM staff_users ORDER BY id DESC").all() : { results: [] };
          
          let charityCampaigns = { results: [] };
          try {
            charityCampaigns = await env.DB.prepare("SELECT * FROM charity_campaigns ORDER BY id DESC").all();
          } catch(e) {}

          return j({
            username: admin.username,
            role: admin.role || "moderator",
            creators: creators.results,
            ads: ads.results,
            products: products.results,
            orders: orders.results,
            bookings: bookings.results,
            care_cases: careCases.results,
            polls: polls.results,
            audit_logs: auditLogs.results,
            staff_users: staffUsers.results,
            charity_campaigns: charityCampaigns.results
          });
        }

        if (request.method === "POST") {
          const b = await request.json();
          const action = b.action;
          const id = b.id;
          const data = b.data || {};

          if (path === "/api/admin/charity") {
            try {
              await env.DB.prepare(`
                CREATE TABLE IF NOT EXISTS charity_campaigns (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  banner_url TEXT,
                  target_amount REAL,
                  raised_amount REAL,
                  upi_id TEXT,
                  upi_name TEXT,
                  donate_link TEXT,
                  description TEXT,
                  active INTEGER DEFAULT 1
                )
              `).run();
            } catch(e) {}

            if (action === "create") {
              await env.DB.prepare(
                "INSERT INTO charity_campaigns (title, banner_url, target_amount, raised_amount, upi_id, upi_name, donate_link, description, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)"
              ).bind(data.title, data.banner_url || "", data.target_amount || 0, data.raised_amount || 0, data.upi_id || "", data.upi_name || "", data.donate_link || "", data.description || "").run();
            } else if (action === "update") {
              await env.DB.prepare(
                "UPDATE charity_campaigns SET title = ?, banner_url = ?, target_amount = ?, raised_amount = ?, upi_id = ?, upi_name = ?, donate_link = ?, description = ?, active = ? WHERE id = ?"
              ).bind(data.title, data.banner_url, data.target_amount, data.raised_amount, data.upi_id, data.upi_name, data.donate_link, data.description, data.active ?? 1, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM charity_campaigns WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "CHARITY_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/creators") {
            if (action === "status") {
              await env.DB.prepare("UPDATE creators SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM creators WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "CREATOR_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/ads") {
            if (action === "create") {
              await env.DB.prepare("INSERT INTO ads (title, badge, media_url, target_url, sort, active) VALUES (?, ?, ?, ?, ?, 1)")
                .bind(data.title, data.badge || "", data.media_url || "", data.target_url || "", data.sort || 0).run();
            } else if (action === "update") {
              await env.DB.prepare("UPDATE ads SET title = ?, badge = ?, media_url = ?, target_url = ?, sort = ?, active = ? WHERE id = ?")
                .bind(data.title, data.badge, data.media_url, data.target_url, data.sort || 0, data.active ?? 1, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM ads WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "AD_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/products") {
            if (action === "create") {
              await env.DB.prepare("INSERT INTO products (title, category, description, price_inr, image_url, download_url, active) VALUES (?, ?, ?, ?, ?, ?, 1)")
                .bind(data.title, data.category || "", data.description || "", data.price_inr || 0, data.image_url || "", data.download_url || "").run();
            } else if (action === "update") {
              await env.DB.prepare("UPDATE products SET title = ?, category = ?, description = ?, price_inr = ?, image_url = ?, download_url = ?, active = ? WHERE id = ?")
                .bind(data.title, data.category, data.description, data.price_inr, data.image_url, data.download_url, data.active ?? 1, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "PRODUCT_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/orders") {
            if (action === "status") {
              await env.DB.prepare("UPDATE orders SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM orders WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "ORDER_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/bookings") {
            if (action === "status") {
              await env.DB.prepare("UPDATE bookings SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM bookings WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "BOOKING_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/care") {
            if (action === "status") {
              await env.DB.prepare("UPDATE care_cases SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM care_cases WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "CARE_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/polls") {
            if (action === "create") {
              const opts = data.options || [];
              const counts = new Array(opts.length).fill(0);
              await env.DB.prepare("INSERT INTO polls (question, options_json, counts_json, total_votes, active) VALUES (?, ?, ?, 0, 1)")
                .bind(data.question, JSON.stringify(opts), JSON.stringify(counts)).run();
            } else if (action === "update") {
              await env.DB.prepare("UPDATE polls SET active = ? WHERE id = ?").bind(data.active ?? 1, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM polls WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "POLL_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/staff") {
            if (isStaff) return j({ error: "Forbidden" }, 403);
            if (action === "create") {
              if (!data.username || !data.password) return j({ error: "Missing username or password" }, 400);
              await env.DB.prepare(
                "INSERT INTO staff_users (username, password, role) VALUES (?, ?, ?)"
              ).bind(data.username, data.password, data.role || "moderator").run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM staff_users WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role || "admin", "STAFF_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: "true" });
          }
        }
      }

      return j({ error: "Not Found" }, 404);
    } catch (err) {
      return j({ error: err.message || "Internal Server Error" }, 500);
    }
  }
};
