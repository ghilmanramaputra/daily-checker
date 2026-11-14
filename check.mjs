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

async function getTargets() {
  const byId = new Map();
  for (const kw of KEYWORDS) for (const it of await searchMercari(kw)) if (!byId.has(it.id)) byId.set(it.id, it);
  return [...byId.values()].filter((it) => isTarget(it.name));
}

// ---------- ntfy ----------
async function notify({ title, message, url, image, tags = ["racing_car"], priority = 4 }) {
  const payload = { topic: NTFY_TOPIC, title, message, priority, tags };
  if (url) { payload.click = url; payload.actions = [{ action: "view", label: "Buka listing", url }]; }
  if (image) payload.attach = image;
  const r = await fetch("https://ntfy.sh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  if (!r.ok) console.log(`ntfy HTTP ${r.status}`);
}

// ---------- state ----------
const loadState = () => (existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8").replace(/^﻿/, "")) : { ids: null, fails: 0 });
const saveState = (s) => writeFileSync(STATE_FILE, JSON.stringify({ ids: s.ids ? s.ids.slice(-2000) : null, fails: s.fails }, null, 0) + "\n");

async function checkOnce(state) {
  let items;
  try {
    items = await getTargets();
  } catch (e) {
    state.fails = (state.fails || 0) + 1;
    console.log(`GAGAL (${state.fails}x berturut-turut): ${e.message}`);
    if (state.fails === 5) await notify({ title: "Watcher Buck Blader bermasalah", message: `5x gagal berturut-turut: ${e.message}`, url: SEARCH_PAGE, tags: ["rotating_light"] });
    return;
  }
  state.fails = 0;

  if (!state.ids) {
    state.ids = items.map((i) => i.id);
    console.log(`Run pertama: ${items.length} listing dicatat.`);
    await notify({ title: "Watcher Buck Blader aktif (GitHub)", message: `${items.length} listing saat ini dicatat. Komputer boleh dimatikan.`, url: SEARCH_PAGE });
    return;
  }

  const seen = new Set(state.ids);
  const fresh = items.filter((i) => !seen.has(i.id));
  for (const n of fresh) {
    console.log(`BARU: ${n.price} yen | ${n.name} | ${n.url}`);
    await notify({ title: `Buck Blader baru: ${n.price.toLocaleString("en-US")} yen`, message: n.name, url: n.url, image: n.thumb });
    state.ids.push(n.id);
  }
  console.log(`OK: ${items.length} listing dicek, ${fresh.length} baru.`);
}

if (!NTFY_TOPIC) { console.log("Secret NTFY_TOPIC belum diisi."); process.exit(1); }
const state = loadState();
for (let i = 0; i < CHECKS; i++) {
  if (i > 0) await new Promise((r) => setTimeout(r, INTERVAL_SEC * 1000));
  await checkOnce(state);
  saveState(state);
}
