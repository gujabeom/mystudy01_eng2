/* 영어 단어 노트 — 단어 세트 목록 · 세트별 단어 · 사이트 설정을 읽어 보여준다.
 * 단어 한 장: 한 줄 핵심(한국식 요약) + COBUILD식 용법 설명(문장으로 뜻 풀이) + 예문 + 같이 쓰는 말 + 헷갈리는 단어.
 * 게시된 사이트: data/content.enc (비밀번호로 암호화한 묶음, scripts/publish_web.py 가 만든다)
 *   암호화 형식은 01_ENG1 · naver_land 와 같다: PBKDF2-SHA256 → AES-256-GCM (+gzip).
 * 로컬 미리보기(web/ 폴더): content.enc 가 없으면 data/*.json 평문을 읽는다.
 * 화면:
 *   #/                 홈 (세트 목록 · 오늘 복습)
 *   #/s/<id>           세트의 단어 목록 (탭하면 펼침)
 *   #/cards/<id|due>   암기 카드 (간격 반복: 몰라요 / 헷갈려요 / 알아요)
 *   #/search?q=        검색
 *   #/ask?cat=&ref=    단어 요청 · 질문 (사이트 설정 feedback 설문지)
 * 본문 표기: **굵게**  __밑줄__  ==형광==  ~~취소~~  줄바꿈(\n)
 */
(() => {
  "use strict";
  const SRS_STORE = "eng2.srs.v1";      // { 단어id: { box: 0~5, due: "YYYY-MM-DD", set } }
  const INTERVALS = [0, 1, 3, 7, 14, 30];   // 상자별 다음 복습까지 날짜
  const $ = (s, el = document) => el.querySelector(s);
  const view = $("#view");
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (s) => esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/__(.+?)__/g, "<u>$1</u>")
    .replace(/==(.+?)==/g, "<mark>$1</mark>")
    .replace(/~~(.+?)~~/g, "<s>$1</s>")
    .replace(/\n/g, "<br>");
  const today = () => new Date().toISOString().slice(0, 10);
  const addDays = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

  // ---------- 데이터 ----------
  let index = null;
  let bundle = null;
  const setCache = new Map();
  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.json();
  }
  async function loadIndex() {
    if (!index) index = bundle ? bundle.index : await getJSON("data/index.json");
    return index;
  }
  async function loadSet(id) {
    if (bundle) {
      if (!bundle.sets[id]) throw new Error(`세트 없음: ${id}`);
      return bundle.sets[id];
    }
    if (!setCache.has(id)) setCache.set(id, await getJSON(`data/sets/${encodeURIComponent(id)}.json`));
    return setCache.get(id);
  }
  async function allWords() {
    const idx = await loadIndex();
    const out = [];
    for (const s of idx.sets.filter((x) => x.status === "ready")) {
      const st = await loadSet(s.id);
      for (const w of st.words) out.push({ ...w, set: s.id, setTitle: st.title });
    }
    return out;
  }

  // ---------- 암기 기록 (간격 반복) ----------
  const srs = (() => {
    let d = {};
    try { d = JSON.parse(store.get(SRS_STORE) || "{}") || {}; } catch { d = {}; }
    const save = () => store.set(SRS_STORE, JSON.stringify(d));
    return {
      get: (id) => d[id],
      grade(id, set, g) {   // g: 0 몰라요, 1 헷갈려요, 2 알아요
        const e = d[id] || { box: 0 };
        e.box = g === 2 ? Math.min(5, e.box + 1) : g === 1 ? Math.max(1, e.box) : 0;
        e.due = addDays(g === 0 ? 0 : INTERVALS[e.box]);
        e.set = set;
        d[id] = e; save();
      },
      known: (set) => Object.values(d).filter((e) => e.set === set && e.box >= 3).length,
      seen: (set) => Object.values(d).filter((e) => e.set === set).length,
      dueIds: () => Object.keys(d).filter((k) => d[k].due <= today()),
    };
  })();

  // ---------- 잠금 (암호화된 내용) ----------
  const KEY_STORE = "eng2.key.v1";
  const b64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  let enc = null;
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decryptWith(key) {
    let plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.iv) }, key, b64(enc.ct));
    if (enc.z === "gzip") {
      const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
      plain = await new Response(ds).arrayBuffer();
    }
    return JSON.parse(new TextDecoder().decode(plain));
  }
  async function tryStoredKey() {
    const raw = store.get(KEY_STORE);
    if (!raw) return false;
    try {
      const s = JSON.parse(raw);
      if (s.salt !== enc.salt || s.iter !== enc.iter) return false;
      const key = await crypto.subtle.importKey("raw", b64(s.key), "AES-GCM", false, ["decrypt"]);
      bundle = await decryptWith(key);
      return true;
    } catch { store.del(KEY_STORE); return false; }
  }
  function showLock(msg) {
    $("#app").hidden = true;
    $("#lock").hidden = false;
    $("#lockMsg").textContent = msg || "";
    $("#pw").focus();
  }
  async function unlock(e) {
    e.preventDefault();
    const btn = $("#unlockBtn");
    btn.disabled = true; btn.textContent = "여는 중…";
    try {
      const key = await deriveKey($("#pw").value, b64(enc.salt), enc.iter);
      bundle = await decryptWith(key);
      if ($("#remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ salt: enc.salt, iter: enc.iter, key: b64e(raw) }));
      }
      $("#pw").value = "";
      start();
    } catch {
      showLock("비밀번호가 맞지 않습니다.");
    } finally {
      btn.disabled = false; btn.textContent = "열기";
    }
  }
  function lockNow() { store.del(KEY_STORE); bundle = null; index = null; showLock(""); }

  // ---------- 난이도 기록 · 질문하기 (01_ENG1 과 같은 설문지 방식) ----------
  const DEVICE_STORE = "eng2.device";
  let dev = store.get(DEVICE_STORE);
  if (!dev) { dev = Math.random().toString(36).slice(2, 10); store.set(DEVICE_STORE, dev); }
  function sendRating(cat, item, kind, value) {
    const c = (window.SITE_CONFIG || {}).rating;
    if (!c?.url) return;
    const f = c.fields;
    const body = new URLSearchParams();
    body.set(f.cat, cat); body.set(f.item, item); body.set(f.kind, kind); body.set(f.value, value); body.set(f.device, dev);
    fetch(c.url, { method: "POST", mode: "no-cors", body }).catch(() => {});
  }
  function feedbackUrl(cat, ref) {
    const f = (window.SITE_CONFIG || {}).feedback || {};
    if (!f.url) return "";
    const q = new URLSearchParams({ usp: "pp_url" });
    if (f.prefill?.category) q.set(f.prefill.category, cat || "단어 요청");
    if (f.prefill?.ref && ref) q.set(f.prefill.ref, ref);
    return `${f.url}?${q}`;
  }
  const askHref = (ref) => `#/ask?${new URLSearchParams(ref ? { ref } : {})}`;

  // ---------- 단어 한 장 ----------
  const levelPill = (lv) => `<span class="pill ${lv === "심화" ? "fl" : lv === "수능" ? "" : "gray"}">${esc(lv)}</span>`;
  function entry(w, setId) {
    const sec = (label, html) => (html ? `<div class="nsec"><div class="nlabel">${label}</div>${html}</div>` : "");
    const q = encodeURIComponent(w.word);
    return `
      <div class="w-core">💡 ${fmt(w.core)}</div>
      ${w.hook ? `<div class="w-hook">${fmt(w.hook)}</div>` : ""}
      ${sec("📖 뜻과 쓰임", `<ol class="senses">${w.senses.map((s) => `<li>
          <div class="def en">${fmt(s.def)}</div>
          <div class="ko">→ <b>${fmt(s.ko)}</b></div>
          <div class="sx en">${fmt(s.ex)}</div>
          ${s.exKo ? `<div class="sxko">${fmt(s.exKo)}</div>` : ""}
        </li>`).join("")}</ol>`)}
      ${sec("🔗 자주 같이 쓰는 말", w.chunks?.length ? `<div class="chunks en">${w.chunks.map((c) => `<span>${fmt(c.en)}${c.ko ? ` <small>${fmt(c.ko)}</small>` : ""}</span>`).join("")}</div>` : "")}
      ${sec("⚖️ 헷갈리는 단어", w.confuse?.length ? `<ul class="nlist">${w.confuse.map((c) => `<li><b class="en">${fmt(c.word)}</b>: ${fmt(c.note)}</li>`).join("")}</ul>` : "")}
      ${sec("📘 문법 연결", w.grammar ? `<p class="small">${fmt(w.grammar)}</p>` : "")}
      <div class="w-links small">
        <a href="https://www.collinsdictionary.com/dictionary/english/${q}" target="_blank" rel="noopener">Collins</a> ·
        <a href="https://en.dict.naver.com/#/search?query=${q}" target="_blank" rel="noopener">네이버 사전</a> ·
        <a href="${askHref(w.word)}">이 단어 질문하기</a>
      </div>
      <div class="rate" data-cat="${esc(setId)}" data-item="${esc(w.id)}">
        <span class="lbl">이 설명은</span>
        <button type="button" data-v="쉬움">쉬워요</button><button type="button" data-v="어려움">어려워요</button>
        <button type="button" data-v="예문 더">예문 더 ＋</button>
        <span class="sent" hidden>✓ 전달됨</span>
      </div>`;
  }
  function wordRow(w, setId) {
    const s = srs.get(w.id);
    const mark = !s ? "" : s.box >= 3 ? `<span class="pill">외움</span>` : `<span class="pill student">복습 중</span>`;
    return `<details class="card word" data-id="${esc(w.id)}">
      <summary><span class="w-word en">${esc(w.word)}</span> <span class="muted small">${esc(w.pos || "")}</span> ${levelPill(w.level)} ${mark}
        <div class="w-sum">${fmt(w.core)}</div></summary>
      <div class="w-body">${entry(w, setId)}</div>
    </details>`;
  }

  // ---------- 화면 ----------
  function renderHome(idx) {
    const groups = [];
    for (const s of idx.sets) {
      let g = groups.find((x) => x.name === s.group);
      if (!g) groups.push((g = { name: s.group, items: [] }));
      g.items.push(s);
    }
    const due = srs.dueIds().length;
    const total = idx.sets.reduce((a, s) => a + (s.counts?.words || 0), 0);
    view.innerHTML = `
      <section class="hero">
        <h2 style="margin:0">단어 · 숙어 노트</h2>
        <p class="muted small">준비된 단어 ${total}개 · 뜻을 외우기보다 '어떤 상황에서 쓰는지'로 익히기</p>
      </section>
      <div class="home-actions">
        <a class="btn" href="#/cards/due">오늘 복습 ${due}개</a>
        <form id="sForm" class="search"><input id="sInput" type="search" placeholder="단어 · 뜻 검색" autocomplete="off"></form>
      </div>
      ${groups.map((g) => `<div class="group-title">${esc(g.name)}</div>
        <div class="cat-list">${g.items.map(setRow).join("")}</div>`).join("")}`;
    $("#sForm").addEventListener("submit", (e) => {
      e.preventDefault();
      location.hash = `#/search?${new URLSearchParams({ q: $("#sInput").value.trim() })}`;
    });
  }
  function setRow(s) {
    const n = s.counts?.words || 0;
    const known = srs.known(s.id);
    const pct = n ? Math.round((known / n) * 100) : 0;
    const inner = `<div class="cat-head"><span class="cat-title">${esc(s.title)}</span>${n ? `<span class="muted small">${n}개</span>` : ""}</div>
      <div class="cat-sub">${esc(s.subtitle || "")}</div>
      ${s.status === "ready" ? `<div class="bar"><span style="width:${pct}%"></span></div><div class="cat-sub">외운 단어 ${known}/${n}</div>`
        : `<div class="cat-sub"><span class="pill gray">준비 중</span></div>`}`;
    return s.status === "ready" ? `<a class="cat" href="#/s/${esc(s.id)}">${inner}</a>` : `<div class="cat planned">${inner}</div>`;
  }
  async function renderSet(id) {
    const st = await loadSet(id);
    view.innerHTML = `
      <a class="crumb" href="#/">← 전체 세트</a>
      <div class="cat-top"><h2>${esc(st.title)}</h2><div class="muted small">${esc(st.subtitle || "")}</div></div>
      <div class="home-actions"><a class="btn" href="#/cards/${esc(id)}">암기 카드로 공부</a>
        <button type="button" class="btn ghost small" id="openAll">모두 펼치기</button></div>
      <div class="words">${st.words.map((w) => wordRow(w, id)).join("")}</div>`;
    $("#openAll").addEventListener("click", (e) => {
      const open = e.target.textContent === "모두 펼치기";
      view.querySelectorAll("details.word").forEach((d) => { d.open = open; });
      e.target.textContent = open ? "모두 접기" : "모두 펼치기";
    });
  }
  async function renderSearch(q) {
    const words = await allWords();
    const t = q.toLowerCase();
    const hits = !t ? [] : words.filter((w) => w.word.toLowerCase().includes(t) || w.core.includes(q)
      || w.senses.some((s) => s.ko.includes(q)) || (w.chunks || []).some((c) => c.en.toLowerCase().includes(t)));
    view.innerHTML = `<a class="crumb" href="#/">← 전체 세트</a>
      <h2>검색: ${esc(q)}</h2>
      <div class="words">${hits.map((w) => wordRow(w, w.set)).join("") || `<div class="empty">찾는 단어가 아직 없습니다.<br><a href="${askHref(q)}">이 단어 만들어 달라고 요청하기</a></div>`}</div>`;
  }

  // 카드 앞면 힌트: 첫 예문에서 그 단어(변화형 포함)를 빈칸으로
  function hintOf(w) {
    const ex = w.senses[0]?.ex;
    if (!ex) return "";
    const head = w.word.split(" ")[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return esc(ex.replace(/\*\*/g, "").replace(new RegExp(`\\b${head}\\w*`, "ig"), "＿＿＿"));
  }
  // 암기 카드: 앞면(단어) → 탭 → 뒷면(핵심 + 뜻) → 몰라요 / 헷갈려요 / 알아요
  async function renderCards(id) {
    let deck;
    if (id === "due") {
      const due = new Set(srs.dueIds());
      deck = (await allWords()).filter((w) => due.has(w.id));
    } else {
      const st = await loadSet(id);
      deck = st.words.map((w) => ({ ...w, set: id }));
      deck.sort((a, b) => ((srs.get(a.id)?.box ?? -1) - (srs.get(b.id)?.box ?? -1)));   // 안 본 것 · 약한 것 먼저
    }
    let i = 0;
    const draw = () => {
      if (i >= deck.length) {
        view.innerHTML = `<a class="crumb" href="#/">← 전체 세트</a>
          <div class="card fc-done"><h2>끝!</h2><p>${deck.length ? `${deck.length}장을 모두 봤습니다.` : "지금 복습할 카드가 없습니다."}</p>
          <p class="muted small">'몰라요'는 오늘 다시, '헷갈려요'는 내일, '알아요'는 점점 간격을 늘려 다시 나옵니다.</p>
          <a class="btn" href="#/">홈으로</a></div>`;
        return;
      }
      const w = deck[i];
      view.innerHTML = `<a class="crumb" href="${id === "due" ? "#/" : `#/s/${esc(id)}`}">← 그만하기</a>
        <div class="fc-count muted small">${i + 1} / ${deck.length}</div>
        <div class="card fc" id="fc">
          <div class="fc-front"><div class="fc-word en">${esc(w.word)}</div><div class="muted">${esc(w.pos || "")}</div>
            <div class="fc-hint muted small">${hintOf(w)}</div>
            <div class="muted small" style="margin-top:16px">탭해서 뜻 보기</div></div>
          <div class="fc-back" hidden><div class="fc-word en fc-word-sm">${esc(w.word)} <span class="muted small">${esc(w.pos || "")}</span></div>${entry(w, w.set)}</div>
        </div>
        <div class="fc-btns" hidden>
          <button type="button" class="btn ghost" data-g="0">몰라요</button>
          <button type="button" class="btn ghost" data-g="1">헷갈려요</button>
          <button type="button" class="btn" data-g="2">알아요</button>
        </div>`;
      const fc = $("#fc");
      $(".fc-front", fc).addEventListener("click", () => {
        $(".fc-front", fc).hidden = true; $(".fc-back", fc).hidden = false; $(".fc-btns").hidden = false;
      });
      view.querySelectorAll("[data-g]").forEach((b) => b.addEventListener("click", () => {
        const g = Number(b.dataset.g);
        srs.grade(w.id, w.set, g);
        sendRating(w.set, w.id, "암기", ["몰라요", "헷갈려요", "알아요"][g]);
        if (g === 0) deck.push(w);   // 몰라요는 이번에 한 번 더
        i += 1; draw(); window.scrollTo(0, 0);
      }));
    };
    draw();
  }

  function renderAsk(params) {
    const ref = params.get("ref") || "";
    const url = feedbackUrl("단어 요청", ref);
    view.innerHTML = `<h2>단어 요청 · 질문</h2>
      <div class="card">
        <p>사이트에 없는 단어, 교재에서 본 숙어, 헷갈리는 쓰임을 올려 주세요. 같은 형식(한 줄 핵심 + 쓰임 설명 + 예문)으로 추가합니다.</p>
        <ul class="small"><li>단어장·지문 사진을 올려도 됩니다.</li><li>어느 문장에서 봤는지 적어 주면 그 뜻을 중심으로 만듭니다.</li></ul>
        ${ref ? `<p class="small muted">자동으로 채워지는 정보: <b>${esc(ref)}</b></p>` : ""}
        ${url ? `<a class="btn" style="width:100%" href="${esc(url)}" target="_blank" rel="noopener">올리기 화면 열기</a>`
          : `<div class="notice">아직 올리기 채널이 연결되지 않았습니다 (data/site-config.json).</div>`}
      </div>`;
  }

  // ---------- 공통 클릭 ----------
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".rate button");
    if (!b || b.disabled) return;
    const bar = b.closest(".rate");
    sendRating(bar.dataset.cat, bar.dataset.item, b.dataset.v === "예문 더" ? "요청" : "평가", b.dataset.v);
    b.classList.add("on"); b.disabled = true;
    bar.querySelector(".sent").hidden = false;
  });

  // ---------- 라우터 ----------
  async function route() {
    const raw = location.hash.replace(/^#/, "") || "/";
    const [path, qs] = raw.split("?");
    const parts = path.split("/").filter(Boolean);
    try {
      const idx = await loadIndex();
      $("#builtAt").textContent = idx.updated ? `내용 업데이트 ${idx.updated}` : "";
      $("#dueCount").textContent = srs.dueIds().length || "";
      $("#dueCount").hidden = !srs.dueIds().length;
      if (parts[0] === "s" && parts[1]) await renderSet(parts[1]);
      else if (parts[0] === "cards" && parts[1]) await renderCards(parts[1]);
      else if (parts[0] === "search") await renderSearch(new URLSearchParams(qs || "").get("q") || "");
      else if (parts[0] === "ask") renderAsk(new URLSearchParams(qs || ""));
      else renderHome(idx);
    } catch (err) {
      view.innerHTML = `<p class="notice">내용을 불러오지 못했습니다. 잠시 뒤 새로고침해 주세요.<br><span class="small">${esc(err.message)}</span></p>`;
    }
    window.scrollTo(0, 0);
  }
  let started = false;
  function start() {
    window.SITE_CONFIG = bundle ? bundle.config : window.SITE_CONFIG;
    $("#lock").hidden = true;
    $("#app").hidden = false;
    $("#lockBtn").hidden = !enc;
    if (!started) { window.addEventListener("hashchange", route); started = true; }
    route();
  }
  async function boot() {
    $("#lockForm").addEventListener("submit", unlock);
    $("#lockBtn").addEventListener("click", lockNow);
    const r = await fetch("data/content.enc", { cache: "no-cache" }).catch(() => null);
    if (r && r.ok) {
      enc = await r.json();
      if (await tryStoredKey()) start(); else showLock("");
    } else {
      window.SITE_CONFIG = await getJSON("data/site-config.json").catch(() => ({}));
      start();
    }
  }
  boot();
})();
