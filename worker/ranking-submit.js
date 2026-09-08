// Cloudflare Worker: authenticates on the player's behalf and files a
// ranking submission as a GitHub issue, so the accompanying
// .github/workflows/ranking.yml action can validate it and update
// ranking-clear.json exactly as before (same pattern as tetris-ninniku).
//
// Anti-cheat: a run must first fetch a one-time start token from POST
// /start (issued at the moment the player presses Start). The token is a
// random id stored server-side in a KV namespace, keyed by the token and
// holding the issue timestamp. Submitting a score:
//   1. requires the token to exist in KV (i.e. it was really issued, and
//      not already used) - this makes every token single-use, closing the
//      "capture one request in DevTools and resend it forever" replay hole
//   2. is rejected unless the claimed clear time is no faster than the
//      real wall-clock time that has actually elapsed since the token was
//      issued (with a small tolerance for timer/network imprecision) -
//      this closes the "POST an arbitrary value without ever playing" hole
// The token is deleted from KV the moment it's consumed (valid or not,
// once looked up it can never be reused), so a captured request can only
// ever register once, no matter how many times it's resent.
//
// Deploy this as-is in the Cloudflare dashboard (Workers & Pages ->
// select this Worker -> paste this file), then:
//   1. Add an encrypted environment variable GITHUB_TOKEN: a fine-grained
//      GitHub personal access token scoped ONLY to this repo
//      (pix-co/running-ninniku) with "Issues: Read and write" permission.
//   2. Create a KV namespace (Workers & Pages -> KV -> Create namespace,
//      any name e.g. "running-ninniku-ranking-tokens") and bind it to
//      this Worker under Settings -> Variables -> KV Namespace Bindings,
//      with the binding name RANKING_TOKENS (must match exactly).
// The previous RANKING_SIGNING_KEY secret is no longer used and can be
// removed (harmless to leave it too).

const REPO_OWNER = 'pix-co';
const REPO_NAME = 'running-ninniku';
const ALLOWED_ORIGIN = 'https://pix-co.github.io';

const TOKEN_MAX_AGE_SEC = 30 * 60;             // 一時停止等の余裕を見て30分まで有効
const CLOCK_TOLERANCE_MS = 1500;               // タイマー精度・通信遅延の許容誤差
const MIN_CLEAR_MS = 3000;                     // 理論上の最速(約5.6秒)より十分短い絶対下限

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
      const token = crypto.randomUUID();
      await env.RANKING_TOKENS.put(token, String(Date.now()), { expirationTtl: TOKEN_MAX_AGE_SEC });
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

    const token = typeof data.token === 'string' ? data.token : '';
    const issuedAtStr = token ? await env.RANKING_TOKENS.get(token) : null;
    if(issuedAtStr === null){
      // 未発行・期限切れ(KVのTTLで自動失効)・もしくは既に一度使用済みのトークン
      return jsonResponse({ ok:false, error:'missing, expired, or already-used start token' }, 400);
    }
    // 一度読んだトークンはここで即座に無効化する(検証結果に関わらず、以後の再送は必ず失敗する)
    await env.RANKING_TOKENS.delete(token);

    const tokenAge = Date.now() - Number(issuedAtStr);
    if(!Number.isFinite(tokenAge) || tokenAge < 0){
      return jsonResponse({ ok:false, error:'invalid start token' }, 400);
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
