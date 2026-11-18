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
        
        // Direct validation for easy access
        if (username !== "OWNER_SETUP_KEY" || password !== "AKSHAY2007ADMIN") {
          return j({ error: "Invalid username or password" }, 401);
        }

        const token = await sha256Hex(username + Math.random() + Date.now());
        
        try {
          await env.DB.prepare(
            "UPDATE admins SET token = ?, token_created_at = ? WHERE id = 1"
          ).bind(token, Math.floor(Date.now() / 1000)).run();
        } catch(e) {}

        await logAudit(env, username, "superadmin", "ADMIN_LOGIN", "Successful login");
        return j({ token, username: "OWNER_SETUP_KEY", role: "superadmin" });
      }

      if (request.method === "GET" && path === "/api/public/overview") {
        const creators = await env.DB.prepare("SELECT * FROM creators WHERE status = 'approved' ORDER BY id DESC").all();
        const ads = await env.DB.prepare("SELECT * FROM ads WHERE active = 1 ORDER BY sort ASC, id DESC").all();
        const products = await env.DB.prepare("SELECT * FROM products WHERE active = 1 ORDER BY id DESC").all();
        const polls = await env.DB.prepare("SELECT * FROM polls WHERE active = 1 ORDER BY id DESC").all();

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
          polls: pollsWithOpts
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
        const admin = await env.DB.prepare("SELECT * FROM admins WHERE token = ?").bind(token).first();
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

          return j({
            username: admin.username,
            role: admin.role,
            creators: creators.results,
            ads: ads.results,
            products: products.results,
            orders: orders.results,
            bookings: bookings.results,
            care_cases: careCases.results,
            polls: polls.results,
            audit_logs: auditLogs.results
          });
        }

        if (request.method === "POST") {
          const b = await request.json();
          const action = b.action;
          const id = b.id;
          const data = b.data || {};

          if (path === "/api/admin/creators") {
            if (action === "status") {
              await env.DB.prepare("UPDATE creators SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM creators WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role, "CREATOR_" + action.toUpperCase(), `ID: ${id}`);
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
            await logAudit(env, admin.username, admin.role, "AD_" + action.toUpperCase(), `ID: ${id}`);
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
            await logAudit(env, admin.username, admin.role, "PRODUCT_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/orders") {
            if (action === "status") {
              await env.DB.prepare("UPDATE orders SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM orders WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role, "ORDER_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/bookings") {
            if (action === "status") {
              await env.DB.prepare("UPDATE bookings SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM bookings WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role, "BOOKING_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if (path === "/api/admin/care") {
            if (action === "status") {
              await env.DB.prepare("UPDATE care_cases SET status = ? WHERE id = ?").bind(b.status, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE FROM care_cases WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role, "CARE_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }

          if, path === "/api/admin/polls") {
            if (action === "create") {
              const opts = data.options || [];
              const counts = new Array(opts.length).fill(0);
              await env.DB.prepare("INSERT INTO polls (question, options_json, counts_json, total_votes, active) VALUES (?, ?, ?, 0, 1)")
                .bind(data.question, JSON.stringify(opts), JSON.stringify(counts)).run();
            } else if (action === "update") {
              await env.DB.prepare("UPDATE polls SET active = ? WHERE id = ?").bind(data.active ?? 1, id).run();
            } else if (action === "delete") {
              await env.DB.prepare("DELETE polls WHERE id = ?").bind(id).run();
            }
            await logAudit(env, admin.username, admin.role, "POLL_" + action.toUpperCase(), `ID: ${id}`);
            return j({ success: true });
          }
        }
      }

      return j({ error: "Not Found" }, 404);
    } catch (err) {
      return j({ error: err.message || "Internal Server Error" }, 500);
    }
  }
};
