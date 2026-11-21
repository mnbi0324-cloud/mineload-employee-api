const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8'
};
const json = (body, status=200) => new Response(JSON.stringify(body), {status, headers:cors});
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, {headers:cors});
    if (request.method !== 'POST') return json({error:'Method not allowed'},405);
    if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) return json({error:'Worker secrets are not configured'},500);
    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) return json({error:'Missing login token'},401);
    const token = auth.slice(7);
    const callerRes = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` }
    });
    if (!callerRes.ok) return json({error:'Invalid login session'},401);
    const caller = await callerRes.json();
    const profileRes = await fetch(`${env.SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(caller.id)}&select=role`, {
      headers: {apikey:env.SUPABASE_SERVICE_ROLE_KEY, Authorization:`Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`}
    });
    if (!profileRes.ok) return json({error:'Could not verify admin role'},500);
    const profiles = await profileRes.json();
    if (!profiles.some(p => p.role === 'admin')) return json({error:'Admin permission required'},403);
    let body;
    try { body = await request.json(); } catch { return json({error:'Invalid JSON'},400); }
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const display_name = String(body.display_name || '').trim();
    const permissions = body.permissions && typeof body.permissions === 'object' ? body.permissions : {};
    if (!email || password.length < 8 || !display_name) return json({error:'Name, email and password (8+ characters) are required'},400);
    const createRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
      method:'POST', headers:{apikey:env.SUPABASE_SERVICE_ROLE_KEY, Authorization:`Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type':'application/json'},
      body:JSON.stringify({email,password,email_confirm:true,user_metadata:{display_name}})
    });
    const created = await createRes.json();
    if (!createRes.ok) return json({error:created.msg || created.message || created.error || 'Could not create user'},createRes.status);
    const profileUpsert = await fetch(`${env.SUPABASE_URL}/rest/v1/profiles`, {
      method:'POST', headers:{apikey:env.SUPABASE_SERVICE_ROLE_KEY, Authorization:`Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type':'application/json', Prefer:'resolution=merge-duplicates'},
      body:JSON.stringify({id:created.id,display_name,role:'employee',is_active:true})
    });
    if (!profileUpsert.ok) return json({error:'Account created but profile write failed. Contact admin.'},500);
    const permUpsert = await fetch(`${env.SUPABASE_URL}/rest/v1/employee_permissions`, {
      method:'POST', headers:{apikey:env.SUPABASE_SERVICE_ROLE_KEY, Authorization:`Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, 'Content-Type':'application/json', Prefer:'resolution=merge-duplicates'},
      body:JSON.stringify({user_id:created.id,permissions})
    });
    if (!permUpsert.ok) return json({error:'Account and profile created, but permission write failed.'},500);
    return json({success:true,user_id:created.id});
  }
};.
