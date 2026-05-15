import express from "express";
import crypto from "crypto";
import { readFileSync, writeFileSync, existsSync } from 'fs';
const app = express();
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  next();
});
app.use(express.json());

const PORT = process.env.PORT || 3000;
let latestOutput = {};
let isRunning = false;

// ── SIMPLE PASSWORD PROTECTION ──
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'changeme';
const SESSION_TOKEN = crypto.randomBytes(32).toString('hex');
const activeSessions = new Set();

// Login page
app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Cinderella — Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#0A7A7A,#5DCFC9 50%,#F4C0D1);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .box{background:#fff;border-radius:20px;padding:40px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,0.15)}
    .logo{font-family:Georgia,serif;font-size:28px;color:#0A7A7A;font-style:italic;text-align:center;margin-bottom:6px}
    .sub{font-size:12px;color:#9a9994;text-align:center;margin-bottom:28px;letter-spacing:.06em;text-transform:uppercase}
    input{width:100%;border:1px solid #e0e0e0;border-radius:10px;padding:12px 14px;font-size:14px;margin-bottom:14px;outline:none;transition:border-color .2s}
    input:focus{border-color:#0A7A7A}
    button{width:100%;background:linear-gradient(90deg,#0A7A7A,#0E9E9E);color:#fff;border:none;border-radius:10px;padding:12px;font-size:14px;font-weight:500;cursor:pointer}
    button:hover{opacity:.9}
    .err{color:#E24B4A;font-size:12px;text-align:center;margin-bottom:10px;display:none}
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">Cinderella</div>
    <div class="sub">Executive Assistant · Risk 2 Solution</div>
    <div class="err" id="err">Incorrect password. Please try again.</div>
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Enter password" autofocus />
      <button type="submit">Sign in</button>
    </form>
  </div>
  <script>
    if (window.location.search.includes('error')) {
      document.getElementById('err').style.display = 'block';
    }
  </script>
</body>
</html>`);
});

// Handle login form submission
app.post('/login', express.urlencoded({ extended: false }), (req, res) => {
  if (req.body.password === DASHBOARD_PASSWORD) {
    const token = crypto.randomBytes(16).toString('hex');
    activeSessions.add(token);
    res.setHeader('Set-Cookie', `cin_session=${token}; Path=/; HttpOnly; Max-Age=86400`);
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

// Logout
app.get('/logout', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cin_session=([^;]+)/);
  if (match) activeSessions.delete(match[1]);
  res.setHeader('Set-Cookie', 'cin_session=; Path=/; Max-Age=0');
  res.redirect('/login');
});

// Auth middleware — protect everything except /login
function requireAuth(req, res, next) {
  // Allow login, logout and checkin through without password
  if (req.path === '/login' || req.path === '/logout' || req.path === '/checkin') return next();
  // Check session cookie
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cin_session=([^;]+)/);
  if (match && activeSessions.has(match[1])) return next();
  // Not authenticated - redirect to login
  res.redirect('/login');
}

// ── STAFF CHECK-IN (public — no password) ──
app.get('/checkin', (req, res) => {
  res.sendFile('checkin.html', { root: '.' });
});

app.use(requireAuth);

// ── MICROSOFT GRAPH CONFIG ──
const TENANT_ID     = process.env.AZURE_TENANT_ID;
const CLIENT_ID     = process.env.AZURE_CLIENT_ID;
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;
const REDIRECT_URI  = process.env.REDIRECT_URI || 'https://cinderella-agent-abbacse9gbhcaqeu.australiaeast-01.azurewebsites.net/auth/callback';
const SCOPES        = 'offline_access Mail.Read Mail.ReadShared Calendars.ReadWrite Chat.Read ChannelMessage.Read.All';

// ── TOKEN STORE: Persistent file-based storage for Azure ──
const TOKEN_PATH = process.env.TOKEN_STORE_PATH || '/home/tokens.json';

function loadSavedToken() {
  try {
    if (existsSync(TOKEN_PATH)) {
      const data = JSON.parse(readFileSync(TOKEN_PATH, 'utf8'));
      if (data.expires_at && new Date(data.expires_at) > new Date()) {
        console.log('✅ Loaded M365 token from disk (expires', new Date(data.expires_at).toLocaleString(), ')');
        return data;
      }
      console.log('⚠ Saved token expired');
    }
  } catch(e) { console.warn('Token load error:', e.message); }
  return { access_token: null, refresh_token: null, expires_at: null };
}

function persistToken(store) {
  try {
    writeFileSync(TOKEN_PATH, JSON.stringify(store, null, 2));
    console.log('✅ M365 token saved to disk');
  } catch(e) { console.warn('Token save error:', e.message); }
}

let tokenStore = loadSavedToken();

// ── AUTH: Redirect Kandia to Microsoft login ──
app.get('/auth/login', (req, res) => {
  const url = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize`
    + `?client_id=${CLIENT_ID}`
    + `&response_type=code`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    + `&scope=${encodeURIComponent(SCOPES)}`
    + `&response_mode=query`;
  res.redirect(url);
});

// ── AUTH: Handle callback and store tokens ──
app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`Auth error: ${error}`);
  if (!code) return res.send('No code received');
  try {
    const response = await fetch(
      `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code'
        })
      }
    );
    const data = await response.json();
    if (data.error) return res.send(`Token error: ${data.error_description}`);
    tokenStore.access_token  = data.access_token;
    tokenStore.refresh_token = data.refresh_token;
    tokenStore.expires_at    = Date.now() + (data.expires_in * 1000);
    persistToken(tokenStore);
    console.log('✅ Microsoft 365 connected and token saved to disk');
    res.send(`
      <html><body style="font-family:sans-serif;padding:40px;text-align:center;background:#f0efe9">
        <h2 style="color:#0A7A7A">✅ Cinderella is now connected to Microsoft 365</h2>
        <p style="color:#5a5a56">Outlook, Calendar and Teams are authorised.</p>
        <p style="color:#5a5a56">You can close this window and return to the dashboard.</p>
      </body></html>
    `);
  } catch (err) {
    res.send(`Error: ${err.message}`);
  }
});

// ── AUTH: Check connection status ──
app.get('/auth/status', (req, res) => {
  res.json({ connected: !!tokenStore.access_token });
});

// ── AUTH: Refresh token if expired ──
async function getValidToken() {
  if (!tokenStore.access_token) throw new Error('Not connected — visit /auth/login to connect Microsoft 365');
  if (Date.now() < tokenStore.expires_at - 60000) return tokenStore.access_token;
  const response = await fetch(
    `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: tokenStore.refresh_token,
        grant_type: 'refresh_token'
      })
    }
  );
  const data = await response.json();
  if (data.error) throw new Error(`Token refresh failed: ${data.error_description}`);
  tokenStore.access_token  = data.access_token;
  tokenStore.refresh_token = data.refresh_token || tokenStore.refresh_token;
  tokenStore.expires_at    = Date.now() + (data.expires_in * 1000);
  return tokenStore.access_token;
}

// ── GRAPH API HELPER ──
async function graphGet(path, extraHeaders = {}) {
  const token = await getValidToken();
  const response = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    headers: { Authorization: `Bearer ${token}`, ...extraHeaders }
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error?.message || `Graph error ${response.status}`);
  }
  return response.json();
}

// ── EMAILS: Get unreplied emails (cross-referenced with Sent Items) ──
app.get('/graph/emails', async (req, res) => {
  try {
    const fourteenDaysAgo = new Date(Date.now() - 14*24*60*60*1000).toISOString();

    // Fetch inbox and sent items in parallel
    const [inboxData, sentData] = await Promise.all([
      graphGet(`/me/mailFolders/inbox/messages?$filter=receivedDateTime ge ${fourteenDaysAgo}&$orderby=receivedDateTime desc&$top=80&$select=subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments,conversationId`),
      graphGet(`/me/mailFolders/sentitems/messages?$filter=createdDateTime ge ${fourteenDaysAgo}&$select=conversationId&$top=100`)
    ]);

    // Build set of conversation IDs already replied to
    const repliedConversations = new Set(
      (sentData.value || []).map(m => m.conversationId).filter(Boolean)
    );

    const noReply = ['noreply','no-reply','donotreply','do-not-reply','mailer-daemon','notifications@','notification@','automated@','alerts@','alert@','newsletter','@bounce','postmaster','news@','updates@','subscriptions@','unsubscribe','no_reply'];
    const skipKeywords = ['capcoal','unsubscribe','notification','automated message','out of office','auto-reply','autoreply','luxury escapes','island printing','special offer','limited time','click here','dear customer','dear valued','winner','prize','survey','feedback request','receipt for','payment confirmation','order confirmation','shipping confirmation','your order','invoice #','statement of account'];
    const spamDomains = ['luxuryescapes','islandprinting','mailchimp','constantcontact','campaignmonitor','sendgrid','klaviyo','hubspot','marketo','pardot'];

    const emails = inboxData.value
      .filter(m => {
        const addr = (m.from?.emailAddress?.address || '').toLowerCase();
        const name = (m.from?.emailAddress?.name || '').toLowerCase();
        const subj = (m.subject || '').toLowerCase();
        if (noReply.some(p => addr.includes(p))) return false;
        if (skipKeywords.some(p => subj.includes(p) || addr.includes(p))) return false;
        if (spamDomains.some(p => addr.includes(p))) return false;
        if (name.includes('automated') || name.includes('no reply') || name.includes('no-reply')) return false;
        // Exclude if already replied to in this conversation
        if (m.conversationId && repliedConversations.has(m.conversationId)) return false;
        return true;
      })
      .slice(0, 25)
      .map(m => ({
        id: m.id,
        subject: m.subject,
        from: m.from?.emailAddress?.name || m.from?.emailAddress?.address,
        fromEmail: m.from?.emailAddress?.address,
        received: m.receivedDateTime,
        preview: m.bodyPreview?.substring(0, 300),
        hasAttachments: m.hasAttachments || false,
        isRead: m.isRead || false,
        conversationId: m.conversationId,
        hoursOld: Math.round((Date.now() - new Date(m.receivedDateTime)) / 3600000)
      }));
    res.json({ emails });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── EMAILS: Search emails by topic (for meeting prep) ──
app.get('/graph/emails/search', async (req, res) => {
  try {
    const { topic } = req.query;
    if (!topic) return res.json({ emails: [] });
    const data = await graphGet(
      `/me/messages?$search="${encodeURIComponent(topic)}"&$top=10&$select=subject,from,receivedDateTime,bodyPreview,hasAttachments`
    );
    const emails = (data.value || []).map(m => ({
      subject: m.subject,
      from: m.from?.emailAddress?.name || m.from?.emailAddress?.address,
      fromEmail: m.from?.emailAddress?.address,
      received: m.receivedDateTime,
      preview: m.bodyPreview?.substring(0, 200),
      hasAttachments: m.hasAttachments || false,
      hoursOld: Math.round((Date.now() - new Date(m.receivedDateTime)) / 3600000)
    }));
    res.json({ emails });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── CALENDAR: Get today's events ──
app.get('/graph/calendar', async (req, res) => {
  try {
    // Brisbane is UTC+10 (no daylight saving)
    const BRISBANE_OFFSET_MS = 10 * 60 * 60 * 1000;
    const now = new Date();
    // Shift now forward by 10h to get Brisbane's current date
    const brisbaneNow = new Date(now.getTime() + BRISBANE_OFFSET_MS);
    const y = brisbaneNow.getUTCFullYear();
    const m = brisbaneNow.getUTCMonth();
    const d = brisbaneNow.getUTCDate();
    // Brisbane midnight in UTC = subtract 10h offset
    const startOfDay = new Date(Date.UTC(y, m, d, 0, 0, 0) - BRISBANE_OFFSET_MS).toISOString();
    const endOfDay   = new Date(Date.UTC(y, m, d, 23, 59, 59) - BRISBANE_OFFSET_MS).toISOString();
    const data = await graphGet(
      `/me/calendarView?startDateTime=${startOfDay}&endDateTime=${endOfDay}&$orderby=start/dateTime&$select=subject,start,end,location,attendees`,
      { 'Prefer': 'outlook.timezone="Australia/Brisbane"' }
    );
    const events = data.value.map(e => ({
      subject: e.subject,
      start: e.start?.dateTime,
      end: e.end?.dateTime,
      location: e.location?.displayName || '',
      attendees: e.attendees?.map(a => a.emailAddress?.name).filter(Boolean).slice(0, 5)
    }));
    res.json({ events, brisbaneNow });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── CALENDAR: Create an event ──
app.post('/graph/calendar/create', async (req, res) => {
  try {
    const token = await getValidToken();
    const { subject, start, end, attendees, body } = req.body;
    const response = await fetch('https://graph.microsoft.com/v1.0/me/events', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subject,
        start: { dateTime: start, timeZone: 'Australia/Brisbane' },
        end:   { dateTime: end,   timeZone: 'Australia/Brisbane' },
        body:  { contentType: 'text', content: body || '' },
        attendees: (attendees || []).map(email => ({
          emailAddress: { address: email }, type: 'required'
        }))
      })
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    res.json({ success: true, event: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── TEAMS: Get recent unread chats ──
app.get('/graph/teams', async (req, res) => {
  try {
    const chatsData = await graphGet('/me/chats?$top=10');
    const chats = [];
    for (const chat of (chatsData.value || []).slice(0, 8)) {
      try {
        const msgs = await graphGet(`/me/chats/${chat.id}/messages?$top=5`);
        const unread = msgs.value.filter(m => m.body?.content && m.from?.user?.displayName);
        if (unread.length > 0) {
          chats.push({
            chatId: chat.id,
            topic: chat.topic || 'Direct message',
            lastMessage: unread[0]?.body?.content?.replace(/<[^>]*>/g, '').substring(0, 120),
            from: unread[0]?.from?.user?.displayName,
            time: unread[0]?.createdDateTime
          });
        }
      } catch (e) { /* skip chats we can't read */ }
    }
    res.json({ chats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── MONDAY.COM: Get approved boards only ──
const MONDAY_BOARD_IDS = [2031906973, 2005758439]; // Project/Client Feedback + Client Projects ONLY

app.get('/monday/projects', async (req, res) => {
  const apiKey = process.env.MONDAY_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'MONDAY_API_KEY not configured in Render environment variables' });
  try {
    const query = `{
      boards(ids: [2031906973, 2005758439]) {
        id
        name
        state
        items_count
        items_page(limit: 100) {
          items {
            id
            name
            state
            column_values {
              id
              text
            }
          }
        }
      }
    }`;
    const response = await fetch('https://api.monday.com/v2', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': apiKey,
        'API-Version': '2024-01'
      },
      body: JSON.stringify({ query })
    });
    const data = await response.json();
    if (data.errors) return res.status(400).json({ error: data.errors[0]?.message || 'Monday.com error' });

    // Only return the approved boards — safety check
    const boards = (data.data?.boards || []).filter(b => MONDAY_BOARD_IDS.includes(parseInt(b.id))).map(b => ({
      ...b,
      items: b.items_page?.items || []
    }));
    res.json({ boards });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── MONDAY.COM: Get client feedback only ──
app.get('/monday/feedback', async (req, res) => {
  const apiKey = process.env.MONDAY_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'MONDAY_API_KEY not configured' });
  try {
    const query = `{
      boards(ids: [2031906973]) {
        name
        items_page(limit: 50) {
          items {
            id
            name
            column_values {
              text
            }
          }
        }
      }
    }`;
    const response = await fetch('https://api.monday.com/v2', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': apiKey,
        'API-Version': '2024-01'
      },
      body: JSON.stringify({ query })
    });
    const data = await response.json();
    if (data.errors) return res.status(400).json({ error: data.errors[0]?.message });
    res.json({ feedback: data.data?.boards?.[0]?.items_page?.items || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PROXY (forwards chat requests to Claude) ──
app.options('/proxy', (req, res) => res.sendStatus(200));
app.post('/proxy', async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});


// ── DEBUG: Check config (remove after fixing auth) ──
app.get('/debug-auth', requireAuth, (req, res) => {
  res.json({
    clientId: process.env.AZURE_CLIENT_ID || 'NOT SET',
    tenantId: process.env.AZURE_TENANT_ID || 'NOT SET',
    secretLength: (process.env.AZURE_CLIENT_SECRET || '').length,
    secretFirst4: (process.env.AZURE_CLIENT_SECRET || '').substring(0, 4),
    secretLast4: (process.env.AZURE_CLIENT_SECRET || '').slice(-4),
    redirectUri: process.env.REDIRECT_URI || 'NOT SET',
    scopes: SCOPES
  });
});

// ── SERVE DASHBOARD ──
app.use(express.static('.'));

// ── THINK LOOP ──
async function think() {
  if (isRunning) return;
  isRunning = true;
  try {
    let emails = [];
    let calendarSummary = "No calendar data yet";

    if (tokenStore.access_token) {
      try {
        const emailData = await graphGet(
          `/me/messages?$filter=isRead eq false&$top=10&$select=subject,from,receivedDateTime`
        );
        emails = emailData.value.map(m => ({
          sender: m.from?.emailAddress?.name,
          hoursOld: Math.round((Date.now() - new Date(m.receivedDateTime)) / 3600000),
          subject: m.subject
        }));
        const BRISBANE_MS = 10 * 60 * 60 * 1000;
        const nowT = new Date();
        const brisNow = new Date(nowT.getTime() + BRISBANE_MS);
        const ty = brisNow.getUTCFullYear(), tm = brisNow.getUTCMonth(), td = brisNow.getUTCDate();
        const start = new Date(Date.UTC(ty, tm, td, 0, 0, 0) - BRISBANE_MS).toISOString();
        const end   = new Date(Date.UTC(ty, tm, td, 23, 59, 59) - BRISBANE_MS).toISOString();
        const calData = await graphGet(`/me/calendarView?startDateTime=${start}&endDateTime=${end}&$select=subject,start,end`);
        calendarSummary = calData.value.map(e =>
          `${new Date(e.start.dateTime).toLocaleTimeString('en-AU',{hour:'2-digit',minute:'2-digit'})} — ${e.subject}`
        ).join(', ') || 'No meetings today';
      } catch(e) {
        console.log('Graph fetch in think loop:', e.message);
      }
    }

    const staff = []; // Staff data comes from JSONBin check-ins
    const prompt = `You are Cinderella, an elite COO executive assistant. Analyse and return ONLY raw JSON with no markdown.
Emails: ${JSON.stringify(emails)}
Calendar today: ${calendarSummary}
Staff: ${JSON.stringify(staff)}
Return: {"priorities":[{"id":"","task":"","owner":"","urgency":"low|medium|high","reason":""}],"risks":[{"risk":"","impact":"","severity":"low|medium|high"}],"actions":[{"action":"","priority":"low|medium|high","owner":"","rationale":""}]}`;

    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": process.env.ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 1024, messages: [{ role: "user", content: prompt }] })
    });
    if (!res.ok) return;
    const data = await res.json();
    if (data?.content?.[0]?.text) {
      const clean = data.content[0].text.replace(/```json/g,'').replace(/```/g,'').trim();
      try { latestOutput = JSON.parse(clean); } catch(e) {}
    }
  } catch (err) {
    console.error("❌ Error:", err.message);
  } finally {
    isRunning = false;
  }
}

think();
setInterval(think, 300000);

app.get("/status", (req, res) => {
  res.json(Object.keys(latestOutput).length === 0 ? { status: "initialising" } : latestOutput);
});

app.listen(PORT, () => {
  console.log(`🌙 Cinderella running on port ${PORT}`);
});
