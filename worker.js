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