// Buck Blader watcher for GitHub Actions (Node 22, no dependencies)
// Checks Mercari JP for new Tamiya Buck Blader listings and pushes them to the ntfy app.
// State (listings already notified) is kept in seen.json, committed back by the workflow.
//
// Env: NTFY_TOPIC (required), CHECKS (checks per run, default 1), INTERVAL_SEC (gap between checks, default 180)

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const KEYWORDS = ["Buck Blader", "バックブレーダー"];
const MUST_MATCH = ["buckblader", "buckbrader", "バックブレーダー", "バックブレイダー"];
const EXCLUDE = ["トレカ", "カード", "スリーブ"]; // trading cards, cards, card sleeves
const MERCARI_API = "https://api.mercari.jp/v2/entities:search";
const SEARCH_PAGE = "https://jp.mercari.com/search?keyword=" + encodeURIComponent("Buck Blader") + "&sort=created_time&order=desc&status=on_sale";
const YAHOO_PAGE = "https://auctions.yahoo.co.jp/search/search?p=" + encodeURIComponent("バックブレーダー") + "&s1=new&o1=d";
const STATE_FILE = "seen.json";

const NTFY_TOPIC = process.env.NTFY_TOPIC;
const CHECKS = Number(process.env.CHECKS || 1);
const INTERVAL_SEC = Number(process.env.INTERVAL_SEC || 180);

// ---------- title filter ----------
const norm = (s) => (s || "").normalize("NFKC").toLowerCase().replace(/[\s\-_.・]/g, "");
function isTarget(name) {
  const n = norm(name);
  if (EXCLUDE.some((x) => n.includes(x))) return false;
  return MUST_MATCH.some((m) => n.includes(m));
}

// ---------- DPoP token (ES256 JWT that Mercari's API requires) ----------
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const b64uText = (s) => b64u(new TextEncoder().encode(s));

async function makeDpop(url, method) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y } };
  const payload = { iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(), htu: url, htm: method, uuid: crypto.randomUUID() };
  const input = b64uText(JSON.stringify(header)) + "." + b64uText(JSON.stringify(payload));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, new TextEncoder().encode(input));
  return input + "." + b64u(sig);
}

// ---------- Mercari search ----------
async function searchMercari(keyword) {
  const body = {
    userId: "", pageSize: 60, pageToken: "",
    searchSessionId: crypto.randomUUID().replace(/-/g, ""),
    indexRouting: "INDEX_ROUTING_UNSPECIFIED", thumbnailTypes: [],
    searchCondition: {
      keyword, excludeKeyword: "", sort: "SORT_CREATED_TIME", order: "ORDER_DESC", status: ["STATUS_ON_SALE"],
      sizeId: [], categoryId: [], brandId: [], sellerId: [], priceMin: 0, priceMax: 0,
      itemConditionId: [], shippingPayerId: [], shippingFromArea: [], shippingMethod: [],
      colorId: [], hasCoupon: false, attributes: [], itemTypes: [], skuIds: [],
    },
    defaultDatasets: ["DATASET_TYPE_MERCARI", "DATASET_TYPE_BEYOND"], serviceFrom: "suruga",
    withItemBrand: true, withItemSize: false, withItemPromotions: true, withItemSizes: true, withShopname: false,
  };
  const res = await fetch(MERCARI_API, {
    method: "POST",
    headers: {
      DPoP: await makeDpop(MERCARI_API, "POST"),
      "X-Platform": "web",
      "Content-Type": "application/json; charset=utf-8",
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Mercari HTTP ${res.status}: ${(await res.text()).slice(0, 150).replace(/\s+/g, " ")}`);
  const json = await res.json();
  return (json.items || []).map((it) => {
    const shop = it.itemType === "ITEM_TYPE_BEYOND";
    return {
      id: it.id,
      name: it.name,
      price: Number(it.price),
      url: shop ? `https://jp.mercari.com/shops/product/${it.id}` : `https://jp.mercari.com/item/${it.id}`,
      thumb: it.thumbnails && it.thumbnails[0],
    };
  });
}

// ---------- Yahoo! Auctions search ----------
// The search page is a Next.js page; the listings are in its __NEXT_DATA__ JSON.
// Ids are stored as "yahoo:<auctionId>" so they never mix with Mercari ids.
async function searchYahoo(keyword) {
  const url = "https://auctions.yahoo.co.jp/search/search?p=" + encodeURIComponent(keyword) + "&s1=new&o1=d&n=100";
  const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36", "Accept-Language": "ja" } });
  if (!res.ok) throw new Error(`Yahoo HTTP ${res.status}`);
  const m = (await res.text()).match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
  if (!m) throw new Error("Yahoo: data listing tidak ditemukan di halaman");
  const listing = JSON.parse(m[1])?.props?.pageProps?.initialState?.search?.items?.listing;
  if (!listing || !Array.isArray(listing.items)) throw new Error("Yahoo: format halaman berubah");
  return listing.items.map((it) => ({
    id: `yahoo:${it.auctionId}`,
    name: it.title,
    price: Number(it.price),
    url: `https://auctions.yahoo.co.jp/jp/auction/${it.auctionId}`,
    thumb: it.imageUrl,
    yahoo: true,
    kind: it.isFixedPrice ? "Beli langsung" : it.buyNowPrice ? `Lelang (beli langsung ${Number(it.buyNowPrice).toLocaleString("en-US")} yen)` : "Lelang",
    end: it.endTime ? `${it.endTime.slice(8, 10)}/${it.endTime.slice(5, 7)} ${it.endTime.slice(11, 16)} JST` : "",
  }));
}

// Searches every keyword on both sites. A failing site does not block the other one.
async function getTargets() {
  const byId = new Map();
  const errors = [];
  let yahooOk = true;
  for (const kw of KEYWORDS) {
    for (const [site, search] of [["Mercari", searchMercari], ["Yahoo", searchYahoo]]) {
      try {
        for (const it of await search(kw)) if (!byId.has(it.id)) byId.set(it.id, it);
      } catch (e) {
        errors.push(`${site} (${kw}): ${e.message}`);
        if (site === "Yahoo") yahooOk = false;
      }
    }
  }
  return { items: [...byId.values()].filter((it) => isTarget(it.name)), errors, yahooOk };
}

// ---------- ntfy ----------
async function notify({ title, message, url, image, tags = ["racing_car"], priority = 4 }) {
  const payload = { topic: NTFY_TOPIC, title, message, priority, tags };
  if (url) { payload.click = url; payload.actions = [{ action: "view", label: "Buka listing", url }]; }
  if (image) payload.attach = image;
  const r = await fetch("https://ntfy.sh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  if (!r.ok) console.log(`ntfy HTTP ${r.status}`);
}

// ---------- shared state ----------
// seen.json lives in the GitHub repo and is shared with the PC watcher, so whoever finds a
// listing first notifies and records it, and the other one skips it. It is read fresh before
// every check and written through the GitHub API (retrying if the other side wrote in between).
// Without GITHUB_TOKEN (local testing) a local seen.json is used instead.
const GH_TOKEN = process.env.GITHUB_TOKEN;
const GH_URL = `https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/contents/${STATE_FILE}`;
const ghHeaders = () => ({ Authorization: `Bearer ${GH_TOKEN}`, Accept: "application/vnd.github+json", "User-Agent": "buckblader-watcher" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const parseState = (text) => {
  const s = JSON.parse(text.replace(/^﻿/, ""));
  return { ids: s.ids || null, fails: s.fails || 0 };
};

async function loadState() {
  if (!GH_TOKEN) return { state: existsSync(STATE_FILE) ? parseState(readFileSync(STATE_FILE, "utf8")) : { ids: null, fails: 0 }, sha: null };
  const r = await fetch(GH_URL, { headers: ghHeaders() });
  if (r.status === 404) return { state: { ids: null, fails: 0 }, sha: null };
  if (!r.ok) throw new Error(`GitHub GET ${r.status}`);
  const j = await r.json();
  return { state: parseState(Buffer.from(j.content, "base64").toString("utf8")), sha: j.sha };
}

async function updateState(mutate) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const { state, sha } = await loadState();
    mutate(state);
    if (state.ids) state.ids = state.ids.slice(-2000);
    const text = JSON.stringify(state) + "\n";
    if (!GH_TOKEN) { writeFileSync(STATE_FILE, text); return state; }
    const r = await fetch(GH_URL, {
      method: "PUT",
      headers: ghHeaders(),
      body: JSON.stringify({ message: "Update seen listings", content: Buffer.from(text).toString("base64"), sha: sha || undefined }),
    });
    if (r.ok) return state;
    if (r.status !== 409 && r.status !== 422) throw new Error(`GitHub PUT ${r.status}`);
    await sleep(1000 + Math.random() * 2000); // the PC wrote at the same moment; reload and retry
  }
  throw new Error("Gagal menyimpan seen.json setelah 5x");
}

const addIds = (ids, more) => [...new Set([...(ids || []), ...more])];

async function checkOnce() {
  const { state } = await loadState();
  const { items, errors, yahooOk } = await getTargets();

  if (errors.length) {
    const s = await updateState((st) => { st.fails += 1; });
    console.log(`GAGAL (${s.fails}x berturut-turut): ${errors.join(" | ")}`);
    if (s.fails === 5) await notify({ title: "Watcher Buck Blader bermasalah", message: `5x gagal berturut-turut: ${errors[0]}`, url: SEARCH_PAGE, tags: ["rotating_light"] });
    if (errors.length === KEYWORDS.length * 2) return; // both sites failed, nothing to compare
    state.fails = s.fails;
  }

  // First time Yahoo is checked: record its current listings silently instead of notifying them all.
  if (state.ids && yahooOk && !state.ids.some((id) => id.startsWith("yahoo:"))) {
    const yahooItems = items.filter((i) => i.yahoo);
    if (yahooItems.length) {
      await updateState((st) => { st.ids = addIds(st.ids, yahooItems.map((i) => i.id)); });
      state.ids = addIds(state.ids, yahooItems.map((i) => i.id));
      console.log(`Yahoo pertama kali: ${yahooItems.length} listing dicatat.`);
      await notify({ title: "Yahoo! Auctions ditambahkan", message: `${yahooItems.length} listing Buck Blader di Yahoo! Auctions saat ini dicatat. Listing baru berikutnya akan dikirim.`, url: YAHOO_PAGE });
    }
  }

  if (!state.ids) {
    await updateState((st) => { st.ids = addIds(st.ids, items.map((i) => i.id)); st.fails = 0; });
    console.log(`Run pertama: ${items.length} listing dicatat.`);
    await notify({ title: "Watcher Buck Blader aktif (GitHub)", message: `${items.length} listing saat ini dicatat. Komputer boleh dimatikan.`, url: SEARCH_PAGE });
    return;
  }

  const seen = new Set(state.ids);
  const fresh = items.filter((i) => !seen.has(i.id));
  for (const n of fresh) {
    console.log(`BARU: ${n.price} yen | ${n.name} | ${n.url}`);
    if (n.yahoo) {
      const info = [n.kind, n.end && `berakhir ${n.end}`].filter(Boolean).join(", ");
      await notify({ title: `Buck Blader baru (Yahoo): ${n.price.toLocaleString("en-US")} yen`, message: `${n.name}\n${info}`, url: n.url, image: n.thumb, tags: ["racing_car", "hammer"] });
    } else {
      await notify({ title: `Buck Blader baru: ${n.price.toLocaleString("en-US")} yen`, message: n.name, url: n.url, image: n.thumb });
    }
  }
  const resetFails = !errors.length && state.fails;
  if (fresh.length || resetFails) await updateState((st) => { st.ids = addIds(st.ids, fresh.map((n) => n.id)); if (resetFails) st.fails = 0; });
  console.log(`OK: ${items.length} listing dicek, ${fresh.length} baru.`);
}

if (!NTFY_TOPIC) { console.log("Secret NTFY_TOPIC belum diisi."); process.exit(1); }
for (let i = 0; i < CHECKS; i++) {
  if (i > 0) await sleep(INTERVAL_SEC * 1000);
  try { await checkOnce(); } catch (e) { console.log(`ERROR: ${e.message}`); }
}
