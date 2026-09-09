// Cloudflare Worker: authenticates on the player's behalf and files a
// ranking submission as a GitHub issue, so the accompanying
// .github/workflows/ranking.yml action can validate it and update the
// right ranking-clear*.json file for the stage (mode 'clear' -> stage1,
// 'clear2' -> stage2; same pattern as tetris-ninniku).
//
// Anti-cheat: a run must first fetch a signed start token from POST /start
// (issued at the moment the player presses Start), then include that token
// when submitting the score/time. The submission is rejected unless the
// claimed clear time is no faster than the real wall-clock time that has
// actually elapsed since the token was issued (with a small tolerance for
// timer/network imprecision). This blocks forging a result by POSTing an
// arbitrary value straight from DevTools without ever playing.
//
// This version does NOT use Workers KV (no server-side token storage) -
// tokens are self-contained and verified purely via HMAC signature, so
// there's no per-request KV write and therefore no KV write-quota outage
// risk. The trade-off vs. the KV-backed version: a captured
// token+value pair can be replayed (resent as-is) to register the same
// score again, since there's no server-side "already used" bookkeeping.
// If that becomes a problem again, the KV-backed design (single-use
// tokens) is the fix, but requires enough KV write quota (Workers Paid
// plan) to handle one write per game start.
//
// Deploy this as-is in the Cloudflare dashboard (Workers & Pages ->
// select this Worker -> paste this file), then add TWO encrypted
// environment variables (Settings -> Variables):
//   - GITHUB_TOKEN: a fine-grained GitHub personal access token scoped
//     ONLY to this repo (pix-co/running-ninniku) with "Issues: Read and
//     write" permission (no other scopes needed).
//   - RANKING_SIGNING_KEY: any long random secret string (e.g. 32+ random
//     characters), type "Secret". Only this Worker needs to know it; it
//     is never sent to the client. Used to HMAC-sign start tokens so they
//     can't be forged. (If this secret is still set from before, it can
//     be reused as-is - no need to change it.)
// The RANKING_TOKENS KV binding is no longer used by this version and can
// be left in place (harmless) or removed from the Worker's bindings.
//
// POST /wiki additionally files a community wiki-post submission (RTA
// Info page) as a GitHub issue labeled 'wiki-post', which
// .github/workflows/wiki.yml then appends to wiki-posts.json. This path
// carries no anti-cheat token since it isn't a competitive score - it
// reuses the same GITHUB_TOKEN (Issues: Read and write on this repo is
// already sufficient, no new PAT needed).

const REPO_OWNER = 'pix-co';
const REPO_NAME = 'running-ninniku';
const ALLOWED_ORIGIN = 'https://pix-co.github.io';

const WIKI_CATEGORIES = ['technique', 'stage1', 'stage2', 'misc', 'bug'];
const WIKI_TITLE_MAX = 60;
const WIKI_BODY_MAX = 2000;

const TOKEN_MAX_AGE_MS = 30 * 60 * 1000;       // 一時停止等の余裕を見て30分まで有効
const CLOCK_TOLERANCE_MS = 1500;               // タイマー精度・通信遅延の許容誤差
// モードごとの理論上の最速タイムより十分短い絶対下限(ステージが増えたら追記する)
const MIN_MS_BY_MODE = {
  clear: 3000,   // ステージ1(500m)
  clear2: 4000,  // ステージ2(1000m、氷山などの滑走区間込みでも下限としては十分厳しい)
};

// リプレイ(ジャンプ・空中姿勢の入力だけを記録した配列)のサイズ上限。
// 不正/壊れたリプレイはランキング登録自体を失敗させず、単に付けずに通す。
const REPLAY_MAX_EVENTS = 1000;
const REPLAY_MAX_JSON_LEN = 20000;
function sanitizeReplay(replay){
  if(!Array.isArray(replay) || replay.length === 0 || replay.length > REPLAY_MAX_EVENTS) return null;
  for(const ev of replay){
    if(!Array.isArray(ev) || ev.length < 2 || ev.length > 3) return null;
    if(typeof ev[0] !== 'number' || !Number.isFinite(ev[0]) || ev[0] < 0 || ev[0] > 3600) return null;
    if(ev[1] !== 'j' && ev[1] !== 'lf' && ev[1] !== 'lb') return null;
    if(ev.length === 3 && ev[2] !== 0 && ev[2] !== 1) return null;
  }
  const json = JSON.stringify(replay);
  if(json.length > REPLAY_MAX_JSON_LEN) return null;
  return json;
}

function corsHeaders(){
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(body, status){
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  });
}

async function getHmacKey(env){
  const keyData = new TextEncoder().encode(env.RANKING_SIGNING_KEY || '');
  return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

function bufToHex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex){
  if(typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0) return null;
  const arr = new Uint8Array(hex.length / 2);
  for(let i = 0; i < arr.length; i++){
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if(Number.isNaN(byte)) return null;
    arr[i] = byte;
  }
  return arr;
}

async function issueToken(env){
  const key = await getHmacKey(env);
  const payload = btoa(JSON.stringify({ ts: Date.now() }));
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return payload + '.' + bufToHex(sigBuf);
}

// Returns the token's issue timestamp (ms) if the signature is valid and
// well-formed, or null otherwise.
async function verifyToken(token, env){
  if(typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if(dot < 0) return null;
  const payload = token.slice(0, dot);
  const sigHex = token.slice(dot + 1);
  const sigBytes = hexToBuf(sigHex);
  if(!sigBytes) return null;
  const key = await getHmacKey(env);
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
  if(!valid) return null;
  try{
    const ts = JSON.parse(atob(payload)).ts;
    return Number.isFinite(ts) ? ts : null;
  }catch(e){
    return null;
  }
}

async function createGithubIssue(env, { title, body, labels }){
  return fetch(
    `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/issues`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'running-ninniku-worker',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ title, body, labels }),
    }
  );
}

async function handleWikiSubmit(request, env){
  let data;
  try{
    data = await request.json();
  }catch(e){
    return jsonResponse({ ok:false, error:'invalid json' }, 400);
  }

  const category = String(data.category || '');
  const title = String(data.title || '').replace(/[\r\n]/g, ' ').trim().slice(0, WIKI_TITLE_MAX);
  const body = String(data.body || '').trim().slice(0, WIKI_BODY_MAX);
  let name = String(data.name || '').replace(/[\r\n]/g, '').trim().slice(0, 12);
  if(!name) name = '名無しさん';

  const validCategory = WIKI_CATEGORIES.includes(category);
  const validTitle = title.length > 0;
  const validBody = body.length > 0;

  if(!validCategory || !validTitle || !validBody){
    return jsonResponse({ ok:false, error:'invalid submission' }, 400);
  }

  const issueBody = 'category: ' + category + '\ntitle: ' + title + '\nname: ' + name + '\n---\n' + body;

  const ghRes = await createGithubIssue(env, {
    title: 'Wiki投稿: ' + title,
    body: issueBody,
    labels: ['wiki-post'],
  });

  if(!ghRes.ok){
    const detail = await ghRes.text();
    return jsonResponse({ ok:false, error:'github api error', detail: detail.slice(0, 300) }, 502);
  }

  const issue = await ghRes.json();
  return jsonResponse({ ok:true, issueNumber: issue.number });
}

export default {
  async fetch(request, env){
    if(request.method === 'OPTIONS'){
      return new Response(null, { headers: corsHeaders() });
    }
    if(request.method !== 'POST'){
      return jsonResponse({ ok:false, error:'method not allowed' }, 405);
    }

    const url = new URL(request.url);
    if(url.pathname === '/start'){
      const token = await issueToken(env);
      return jsonResponse({ ok:true, token });
    }
    if(url.pathname === '/wiki'){
      return handleWikiSubmit(request, env);
    }

    let data;
    try{
      data = await request.json();
    }catch(e){
      return jsonResponse({ ok:false, error:'invalid json' }, 400);
    }

    const mode = data.mode;
    const value = Number(data.value);
    let name = String(data.name || '').replace(/[\r\n]/g, '').trim().slice(0, 12);
    if(!name) name = '名無しさん';

    const validMode = Object.prototype.hasOwnProperty.call(MIN_MS_BY_MODE, mode);
    const validValue = validMode && Number.isFinite(value) && value >= MIN_MS_BY_MODE[mode] && value <= 3600000;

    if(!validMode || !validValue){
      return jsonResponse({ ok:false, error:'invalid submission' }, 400);
    }

    const tokenTs = await verifyToken(data.token, env);
    if(tokenTs === null){
      return jsonResponse({ ok:false, error:'missing or invalid start token' }, 400);
    }
    const tokenAge = Date.now() - tokenTs;
    if(tokenAge < 0 || tokenAge > TOKEN_MAX_AGE_MS){
      return jsonResponse({ ok:false, error:'start token expired' }, 400);
    }
    if(value > tokenAge + CLOCK_TOLERANCE_MS){
      return jsonResponse({ ok:false, error:'claimed time exceeds elapsed real time' }, 400);
    }

    const replayJson = sanitizeReplay(data.replay);
    let body = 'mode: ' + mode + '\nvalue: ' + Math.round(value) + '\nname: ' + name;
    if(replayJson) body += '\nreplay: ' + replayJson;

    const ghRes = await createGithubIssue(env, {
      title: 'ランキング登録: ' + name,
      body,
      labels: ['ranking'],
    });

    if(!ghRes.ok){
      const detail = await ghRes.text();
      return jsonResponse({ ok:false, error:'github api error', detail: detail.slice(0, 300) }, 502);
    }

    const issue = await ghRes.json();
    return jsonResponse({ ok:true, issueNumber: issue.number });
  },
};
