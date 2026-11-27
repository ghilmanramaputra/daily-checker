// Scheduled listing checker for GitHub Actions (Node 22, no dependencies)
// Two lanes, both pushed to ntfy with prices in rupiah (BCA bank notes selling rate):
//   BARU      - every new listing that passes the title filter
//   TERMURAH  - a listing cheaper than the cheapest one known so far,
//               plus one summary every morning (first check after 07.00 WIB)
// State is kept in seen.json in the repo and shared with the PC watcher.
//
// What is searched (name, keywords, filters) is not in this repo: it comes from the WATCH_CONFIG
// secret (base64 of config.json), or from a local config.json when run elsewhere.
// Env: NTFY_TOPIC, WATCH_CONFIG, CHECKS (checks per run, default 1), INTERVAL_SEC (default 180)

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const CFG = JSON.parse((process.env.WATCH_CONFIG
  ? Buffer.from(process.env.WATCH_CONFIG.trim(), "base64").toString("utf8")
  : readFileSync(new URL("./config.json", import.meta.url), "utf8")).replace(/^﻿/, ""));
const NAME = CFG.name;
// Public Actions logs: the runner replaces these words with *** wherever they would appear.
if (process.env.GITHUB_ACTIONS) for (const v of [NAME, ...CFG.keywords, ...CFG.mustMatch]) if (v && v.length > 3) console.log(`::add-mask::${v}`);
const KEYWORDS = CFG.keywords;
const MERCARI_API = "https://api.mercari.jp/v2/entities:search";
const SEARCH_PAGE = "https://jp.mercari.com/search?keyword=" + encodeURIComponent(KEYWORDS[0]) + "&sort=created_time&order=desc&status=on_sale";
const STATE_FILE = "seen.json";

const NTFY_TOPIC = process.env.NTFY_TOPIC;
const CHECKS = Number(process.env.CHECKS || 1);
const INTERVAL_SEC = Number(process.env.INTERVAL_SEC || 180);
const DIGEST_HOUR = 7; // morning summary: first check at or after 07.00 WIB
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

// ---------- title filter ----------
const norm = (s) => (s || "").normalize("NFKC").toLowerCase().replace(/[\s\-_.・]/g, "");
const MUST_MATCH = CFG.mustMatch.map(norm);
const EXCLUDE = (CFG.exclude || []).map(norm);
function isTarget(name) {
  const n = norm(name);
  if (EXCLUDE.some((x) => n.includes(x))) return false;
  return MUST_MATCH.some((m) => n.includes(m));
}

// Lane TERMURAH only looks at the complete item, so loose bits never count as "cheapest".
// lowKeep phrases are removed before lowExclude is applied (an item "with extras" stays in).
// A title with lowPartWord counts as a part unless it also has lowWholeWord.
const LOW_EXCLUDE = (CFG.lowExclude || []).map(norm);
const LOW_KEEP = (CFG.lowKeep || []).map(norm);
const LOW_PART = norm(CFG.lowPartWord || ""), LOW_WHOLE = norm(CFG.lowWholeWord || "");
function isLowTarget(it) {
  if (!(it.price > 0) || !isTarget(it.name)) return false;
  let n = norm(it.name);
  for (const k of LOW_KEEP) n = n.split(k).join("");
  if (LOW_EXCLUDE.some((x) => n.includes(x))) return false;
  if (LOW_PART && n.includes(LOW_PART) && !(LOW_WHOLE && n.includes(LOW_WHOLE))) return false;
  return true;
}

// ---------- edition label (shown in the notification, never filters anything) ----------
// Item numbers from the config win; otherwise seller words: 当時物 (vintage) vs 再販/復刻
// (re-release). ntfy turns the tag into an emoji.
function era(name) {
  const E = CFG.era;
  if (!E) return { label: "", tag: "new" };
  const n = (name || "").normalize("NFKC");
  const hasOld = E.old.codes.some((c) => n.includes(c)), hasNew = E.reissue.codes.some((c) => n.includes(c));
  let old = hasOld && !hasNew, reissue = hasNew && !hasOld;
  if (!hasOld && !hasNew) {
    const o = /当時物|当時もの/.test(n), r = /再販|復刻/.test(n);
    old = o && !r; reissue = r && !o;
  }
  if (old) return { label: E.old.label, tag: "jp" };
  if (reissue) return { label: E.reissue.label, tag: "repeat" };
  return { label: E.unknownLabel || "", tag: "grey_question" };
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
// Newest first by default (lane BARU); lane TERMURAH asks for cheapest first and may page on.
async function searchMercariPage(keyword, { sort = "SORT_CREATED_TIME", order = "ORDER_DESC", pageSize = 60, pageToken = "" } = {}) {
  const body = {
    userId: "", pageSize, pageToken,
    searchSessionId: crypto.randomUUID().replace(/-/g, ""),
    indexRouting: "INDEX_ROUTING_UNSPECIFIED", thumbnailTypes: [],
    searchCondition: {
      keyword, excludeKeyword: "", sort, order, status: ["STATUS_ON_SALE"],
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
      "User-Agent": UA,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Mercari HTTP ${res.status}: ${(await res.text()).slice(0, 150).replace(/\s+/g, " ")}`);
  const json = await res.json();
  const items = (json.items || []).map((it) => {
    const shop = it.itemType === "ITEM_TYPE_BEYOND";
    return {
      id: it.id,
      name: it.name,
      price: Number(it.price),
      url: shop ? `https://jp.mercari.com/shops/product/${it.id}` : `https://jp.mercari.com/item/${it.id}`,
      thumb: it.thumbnails && it.thumbnails[0],
    };
  });
  return { items, next: (json.meta && json.meta.nextPageToken) || "" };
}
const searchMercari = async (keyword) => (await searchMercariPage(keyword)).items;

// Lane TERMURAH: the cheapest on-sale Mercari listing that passes the title filter and isLowTarget.
// Results come cheapest first, so the first page holding a match holds the cheapest one.
async function collectLow() {
  let best = null;
  for (const kw of KEYWORDS) {
    let pageToken = "";
    for (let page = 0; page < 3; page++) {
      const { items, next } = await searchMercariPage(kw, { sort: "SORT_PRICE", order: "ORDER_ASC", pageSize: 120, pageToken });
      await sleep(300);
      const hits = items.filter(isLowTarget);
      if (hits.length) {
        const min = hits.reduce((a, b) => (b.price < a.price ? b : a));
        if (!best || min.price < best.price) best = min;
        break;
      }
      if (!next) break;
      pageToken = next;
    }
  }
  return best;
}

// ---------- rupiah rate (rupiah per 1 yen) ----------
// Every price is always shown in rupiah. Rate sources, in this order:
//   1. BCA bank notes selling rate (3 attempts)   2. last BCA rate stored in seen.json
//   3. market mid rate (open.er-api.com, then frankfurter)   4. FALLBACK_RATE
// rateLine() says which one was used.
const FALLBACK_RATE = 116;
let rateCache = null; // { sell, asOf, at, src: "bca" | "stored" | "market" | "fixed" }
async function fetchBcaRate() {
  const res = await fetch("https://www.bca.co.id/id/informasi/kurs", { headers: { "User-Agent": UA, "Accept-Language": "id" }, signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`BCA HTTP ${res.status}`);
  const html = await res.text();
  const row = html.match(/<tr[^>]*code="JPY"[\s\S]*?rate-type="BankNotes-sell">\s*<p>\s*([\d.,]+)\s*<\/p>/);
  if (!row) throw new Error("BCA: baris JPY bank notes tidak ditemukan");
  const sell = Number(row[1].replace(/\./g, "").replace(",", "."));
  if (!(sell > 20 && sell < 1000)) throw new Error(`BCA: nilai kurs tidak wajar (${row[1]})`);
  const when = html.match(/<span>Bank Notes<\/span>\s*<br\s*\/?>\s*<span[^>]*>([^<]+)<\/span>/);
  return { sell, asOf: when ? when[1].trim() : "" };
}

async function fetchMarketRate() {
  for (const url of ["https://open.er-api.com/v6/latest/JPY", "https://api.frankfurter.dev/v1/latest?base=JPY&symbols=IDR"]) {
    try {
      const r = await fetch(url, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(15000) });
      const v = r.ok ? Number(((await r.json()).rates || {}).IDR) : 0;
      if (v > 20 && v < 1000) return Math.round(v * 100) / 100;
    } catch {}
  }
  return 0;
}

// A BCA rate is reused for an hour. Without one, BCA is tried again on every check.
async function getRate(state) {
  if (rateCache && rateCache.src === "bca" && Date.now() - rateCache.at < 3600 * 1000) return rateCache;
  let err = "";
  for (let i = 0; i < 3; i++) {
    try {
      rateCache = { ...(await fetchBcaRate()), at: Date.now(), src: "bca" };
      console.log(`Kurs BCA terbaca: ${rateCache.sell} (${rateCache.asOf})`);
      return rateCache;
    } catch (e) { err = e.message; if (i < 2) await sleep(3000); }
  }
  console.log(`Kurs BCA gagal diambil 3x: ${err}`);
  if (rateCache && rateCache.src === "bca") return rateCache; // older BCA rate read by this process
  if (state && state.rate && state.rate.sell > 0) return (rateCache = { sell: state.rate.sell, asOf: state.rate.asOf || "", at: 0, src: "stored" });
  const mid = await fetchMarketRate();
  if (mid) return (rateCache = { sell: mid, asOf: "", at: 0, src: "market" });
  return (rateCache = { sell: Number(CFG.fallbackRate) || FALLBACK_RATE, asOf: "", at: 0, src: "fixed" });
}

const dots = (n) => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
const rp = (yen, rate) => `Rp ${dots(yen * (rate ? rate.sell : Number(CFG.fallbackRate) || FALLBACK_RATE))}`;
function rateLine(rate) {
  const v = (n) => `Rp ${String(n).replace(".", ",")}/yen`;
  if (!rate) return `Kurs perkiraan ${v(Number(CFG.fallbackRate) || FALLBACK_RATE)} (kurs tidak terbaca)`;
  const when = rate.asOf ? ` (${rate.asOf})` : "";
  if (rate.src === "stored") return `Kurs jual bank notes BCA tersimpan: ${v(rate.sell)}${when}, situs BCA sedang tidak bisa diakses`;
  if (rate.src === "market") return `Kurs pasar ${v(rate.sell)} (cadangan, situs BCA sedang tidak bisa diakses)`;
  if (rate.src === "fixed") return `Kurs perkiraan ${v(rate.sell)} (situs BCA dan kurs cadangan sedang tidak bisa diakses)`;
  return `Kurs jual bank notes BCA: ${v(rate.sell)}${when}`;
}
const lines = (...xs) => xs.filter(Boolean).join("\n");

// Searches every keyword on Mercari. A failing keyword does not block the other one.
async function getTargets() {
  const byId = new Map();
  const errors = [];
  for (const kw of KEYWORDS) {
    try {
      for (const it of await searchMercari(kw)) if (!byId.has(it.id)) byId.set(it.id, it);
    } catch (e) {
      errors.push(`Mercari (${kw}): ${e.message}`);
    }
  }
  return { items: [...byId.values()].filter((it) => isTarget(it.name)), errors };
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
const ghHeaders = () => ({ Authorization: `Bearer ${GH_TOKEN}`, Accept: "application/vnd.github+json", "User-Agent": "daily-checker" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// low: cheapest Mercari listing known ({id, price} in yen), lowHist: listings that were once the
// cheapest and at what price (last 40), digestDate: WIB date of the last morning summary,
// rate: last BCA rate read ({sell, asOf}).
const parseState = (text) => {
  const s = JSON.parse(text.replace(/^﻿/, ""));
  return { ids: s.ids || null, fails: s.fails || 0, low: s.low || null, lowHist: s.lowHist || {}, digestDate: s.digestDate || "", rate: s.rate || null };
};
const emptyState = () => parseState("{}");

async function loadState() {
  if (!GH_TOKEN) return { state: existsSync(STATE_FILE) ? parseState(readFileSync(STATE_FILE, "utf8")) : emptyState(), sha: null };
  const r = await fetch(GH_URL, { headers: ghHeaders() });
  if (r.status === 404) return { state: emptyState(), sha: null };
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
const wibNow = () => new Date(Date.now() + 7 * 3600 * 1000); // read with the UTC getters
const wibDate = () => wibNow().toISOString().slice(0, 10);

async function checkOnce() {
  const { state } = await loadState();
  const rate = await getRate(state);
  const { items, errors } = await getTargets();

  // Lane TERMURAH runs on its own: if it fails, lane BARU still goes on.
  let low = null, lowOk = true;
  try { low = await collectLow(); }
  catch (e) { lowOk = false; console.log(`Pencarian termurah gagal: ${e.message}`); }

  if (errors.length) {
    const s = await updateState((st) => { st.fails += 1; });
    console.log(`GAGAL (${s.fails}x berturut-turut): ${errors.join(" | ")}`);
    if (s.fails === 5) await notify({ title: `Watcher ${NAME} bermasalah`, message: `5x gagal berturut-turut: ${errors[0]}`, url: SEARCH_PAGE, tags: ["rotating_light"] });
    if (errors.length === KEYWORDS.length) return; // every search failed, nothing to compare
    state.fails = s.fails;
  }

  const rateChanged = !!(rate && rate.at && (!state.rate || state.rate.sell !== rate.sell || state.rate.asOf !== rate.asOf));
  const saveRate = (st) => { if (rateChanged) st.rate = { sell: rate.sell, asOf: rate.asOf }; };
  const lowChanged = lowOk && ((low && low.id) !== (state.low && state.low.id) || (low && low.price) !== (state.low && state.low.price));
  const saveLow = (st) => {
    if (!lowOk) return;
    st.low = low ? { id: low.id, price: low.price } : null;
    if (low) {
      const h = { ...st.lowHist };
      delete h[low.id]; // re-insert so the newest entries are the ones kept
      h[low.id] = low.price;
      st.lowHist = Object.fromEntries(Object.entries(h).slice(-40));
    }
  };
  const digestHour = wibNow().getUTCHours() >= DIGEST_HOUR;

  if (!state.ids) {
    await updateState((st) => {
      st.ids = addIds(st.ids, items.map((i) => i.id)); st.fails = 0;
      saveLow(st); saveRate(st);
      if (digestHour) st.digestDate = wibDate();
    });
    console.log(`Run pertama: ${items.length} listing dicatat.`);
    await notify({ title: `Watcher ${NAME} aktif (GitHub)`, message: `${items.length} listing saat ini dicatat. Komputer boleh dimatikan.`, url: SEARCH_PAGE });
    return;
  }

  // Lane BARU
  const seen = new Set(state.ids);
  const fresh = items.filter((i) => !seen.has(i.id));
  for (const n of fresh) {
    console.log(`BARU: ${n.price} yen`); // no title or link: Actions logs of a public repo are public
    const e = era(n.name);
    await notify({ title: `${NAME} baru ${e.label}: ${rp(n.price, rate)}`, message: lines(n.name, rateLine(rate)), url: n.url, image: n.thumb, tags: [e.tag] });
  }

  // Lane TERMURAH: cheaper than the cheapest known so far. With no "low" recorded yet (first check
  // with this feature) it is only recorded. A listing that was already the cheapest once at this
  // price or lower (it only dropped out of the results for a moment) stays quiet.
  if (lowOk && low && state.low && low.price < state.low.price) {
    const before = state.lowHist[low.id];
    if (before === undefined || before > low.price) {
      const e = era(low.name);
      console.log(`TERMURAH: ${low.price} yen (sebelumnya ${state.low.price})`);
      await notify({
        title: `TERMURAH | ${NAME} ${e.label}: ${rp(low.price, rate)}`,
        message: lines(low.name, `Termurah sebelumnya: ${rp(state.low.price, rate)}`, rateLine(rate)),
        url: low.url, image: low.thumb, tags: ["moneybag"], priority: 5,
      });
    }
  }
  // First check with this feature: record today's summary as done so it starts tomorrow.
  const lowFirst = lowOk && !state.low && !state.digestDate;

  // Morning summary, once a day
  const digestDue = lowOk && !!low && digestHour && state.digestDate !== wibDate() && !lowFirst;
  if (digestDue) {
    const e = era(low.name);
    await notify({
      title: `RANGKUMAN PAGI | ${NAME} termurah ${e.label}: ${rp(low.price, rate)}`,
      message: lines(low.name, rateLine(rate)),
      url: low.url, image: low.thumb, tags: ["sunrise"], priority: 3,
    });
    console.log("Rangkuman pagi dikirim.");
  }

  const resetFails = !errors.length && state.fails;
  const markDigest = digestDue || (lowFirst && digestHour);
  if (fresh.length || resetFails || lowChanged || markDigest || rateChanged) {
    await updateState((st) => {
      st.ids = addIds(st.ids, fresh.map((n) => n.id));
      if (resetFails) st.fails = 0;
      saveLow(st); saveRate(st);
      if (markDigest) st.digestDate = wibDate();
    });
  }
  console.log(`OK: ${items.length} listing dicek, ${fresh.length} baru. Termurah: ${lowOk ? (low ? `${low.price} yen = ${rp(low.price, rate)}` : "tidak ada") : "gagal"}.`);
}

if (!NTFY_TOPIC) { console.log("Secret NTFY_TOPIC belum diisi."); process.exit(1); }
for (let i = 0; i < CHECKS; i++) {
  if (i > 0) await sleep(INTERVAL_SEC * 1000);
  try { await checkOnce(); } catch (e) { console.log(`ERROR: ${e.message}`); }
}
