// Cloudflare Worker: authenticates on the player's behalf and files a
// ranking submission as a GitHub issue, so the accompanying
// .github/workflows/ranking.yml action can validate it and update
// ranking-clear.json exactly as before (same pattern as tetris-ninniku).
//
// Anti-cheat: a run must first fetch a signed start token from POST /start
// (issued at the moment the player presses Start), then include that token
// when submitting the clear time. The submission is rejected unless the
// claimed clear time is no faster than the real wall-clock time that has
// actually elapsed since the token was issued (with a small tolerance for
// timer/network imprecision). This blocks forging a result by POSTing an
// arbitrary value straight from DevTools without ever playing.
//
// Deploy this as-is in the Cloudflare dashboard (Workers & Pages ->
// Create -> paste this file), then add TWO encrypted environment
// variables:
//   - GITHUB_TOKEN: a fine-grained GitHub personal access token scoped
//     ONLY to this repo (pix-co/running-ninniku) with "Issues: Read and
//     write" permission (no other scopes needed).
//   - RANKING_SIGNING_KEY: any long random secret string (e.g. 32+ random
//     characters). Only this Worker needs to know it; it is never sent to
//     the client. Used to HMAC-sign start tokens so they can't be forged.

const REPO_OWNER = 'pix-co';
const REPO_NAME = 'running-ninniku';
const ALLOWED_ORIGIN = 'https://pix-co.github.io';

const TOKEN_MAX_AGE_MS = 30 * 60 * 1000; // 一時停止等の余裕を見て30分まで有効
const CLOCK_TOLERANCE_MS = 1500;         // タイマー精度・通信遅延の許容誤差
const MIN_CLEAR_MS = 3000;               // 理論上の最速(約5.6秒)より十分短い絶対下限

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

    const validMode = mode === 'clear';
    const validValue = Number.isFinite(value) && value >= MIN_CLEAR_MS && value <= 3600000;

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

    const body = 'mode: ' + mode + '\nvalue: ' + Math.round(value) + '\nname: ' + name;

    const ghRes = await fetch(
      `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/issues`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'ninniku-chari-ranking-worker',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'ランキング登録: ' + name,
          body,
          labels: ['ranking'],
        }),
      }
    );

    if(!ghRes.ok){
      const detail = await ghRes.text();
      return jsonResponse({ ok:false, error:'github api error', detail: detail.slice(0, 300) }, 502);
    }

    const issue = await ghRes.json();
    return jsonResponse({ ok:true, issueNumber: issue.number });
  },
};
