// Cloudflare Worker: authenticates on the player's behalf and files a
// ranking submission as a GitHub issue, so the accompanying
// .github/workflows/ranking.yml action can validate it and update
// ranking-clear.json exactly as before (same pattern as tetris-ninniku).
//
// Deploy this as-is in the Cloudflare dashboard (Workers & Pages ->
// Create -> paste this file), then add an encrypted environment
// variable named GITHUB_TOKEN holding a fine-grained GitHub personal
// access token scoped ONLY to this repo (pix-co/ninniku-chari) with
// "Issues: Read and write" permission (no other scopes needed).

const REPO_OWNER = 'pix-co';
const REPO_NAME = 'ninniku-chari';
const ALLOWED_ORIGIN = 'https://pix-co.github.io';

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
    const validValue = Number.isFinite(value) && value >= 0 && value <= 3600000;

    if(!validMode || !validValue){
      return jsonResponse({ ok:false, error:'invalid submission' }, 400);
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
