import express from "express";
import crypto from "crypto";
import { readFileSync, writeFileSync, existsSync, appendFileSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'fs';
import { join as pathJoin } from 'path';

// In-memory log of AI calls
const aiCallLog = [];
const LOG_PATH = '/home/ai-calls.log';
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
// Sessions persisted to disk so restarts don't log everyone out
const SESSIONS_PATH = '/home/sessions.json';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

function loadActiveSessions() {
  try {
    const data = JSON.parse(readFileSync(SESSIONS_PATH, 'utf8') || '{}');
    const now = Date.now();
    const valid = new Set();
    for (const [token, expiry] of Object.entries(data)) {
      if (expiry > now) valid.add(token);
    }
    console.log('[Sessions] Loaded', valid.size, 'valid sessions from disk');
    return valid;
  } catch(e) { return new Set(); }
}

function saveActiveSessions(set) {
  try {
    const obj = {};
    const expiry = Date.now() + SESSION_TTL;
    for (const token of set) obj[token] = expiry;
    writeFileSync(SESSIONS_PATH, JSON.stringify(obj));
  } catch(e) { console.warn('[Sessions] Save failed:', e.message); }
}

const activeSessions = loadActiveSessions();

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
    saveActiveSessions(activeSessions);
    console.log('[Sessions] New session saved for', token.substring(0,8)+'...');
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
  if (match) { activeSessions.delete(match[1]); saveActiveSessions(activeSessions); }
  res.setHeader('Set-Cookie', 'cin_session=; Path=/; Max-Age=0');
  res.redirect('/login');
});

// Auth middleware — protect everything except /login
function requireAuth(req, res, next) {
  if (req.path === '/login' || req.path === '/logout' || req.path === '/checkin' || req.path === '/checkins/submit') return next();
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cin_session=([^;]+)/);
  if (match && activeSessions.has(match[1])) return next();
  // API routes get JSON 401 (not HTML redirect) so the dashboard handles it gracefully
  if (req.path.startsWith('/proxy') || req.path.startsWith('/graph') || req.path.startsWith('/monday') || req.path.startsWith('/auth/status') || req.path.startsWith('/openactions') || req.path.startsWith('/generate') || req.path.startsWith('/docs') || req.path.startsWith('/checkins') || req.path.startsWith('/aurora') || req.path.startsWith('/board-report')) {
    return res.status(401).json({ error: { message: 'Session expired — please refresh the page and log in again.' } });
  }
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
const SCOPES        = 'offline_access Mail.Read Mail.ReadWrite Mail.Send Calendars.ReadWrite Chat.Read ChannelMessage.Read.All';

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



// ── EMAILS: Read info@risk2solution.com shared mailbox ──
app.get('/graph/info-emails', async (req, res) => {
  try {
    const fourteenDaysAgo = new Date(Date.now() - 14*24*60*60*1000).toISOString();
    const data = await graphGet(
      `/users/info@risk2solution.com/mailFolders/inbox/messages?$filter=receivedDateTime ge ${fourteenDaysAgo}&$orderby=receivedDateTime desc&$top=30&$select=subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments,conversationId`
    );
    // Fetch sent items to filter out replied conversations
    const sentData = await graphGet(
      `/users/info@risk2solution.com/mailFolders/sentitems/messages?$filter=createdDateTime ge ${fourteenDaysAgo}&$select=conversationId&$top=100`
    ).catch(() => ({ value: [] }));
    const infoReplied = new Set((sentData.value || []).map(m => m.conversationId).filter(Boolean));

    const noReply = ['noreply','no-reply','donotreply','mailer-daemon','notifications@','automated@','newsletter','@bounce'];
    const skipKeywords = ['unsubscribe','capcoal','luxury escapes','island printing','out of office','auto-reply','automated'];

    const emails = (data.value || [])
      .filter(m => {
        const addr = (m.from?.emailAddress?.address || '').toLowerCase();
        const subj = (m.subject || '').toLowerCase();
        if (noReply.some(p => addr.includes(p))) return false;
        if (skipKeywords.some(p => subj.includes(p) || addr.includes(p))) return false;
        if (m.conversationId && infoReplied.has(m.conversationId)) return false;
        return true;
      })
      .slice(0, 15)
      .map(m => ({
        id: m.id,
        subject: m.subject,
        from: m.from?.emailAddress?.name || m.from?.emailAddress?.address,
        fromEmail: m.from?.emailAddress?.address,
        received: m.receivedDateTime,
        preview: m.bodyPreview?.substring(0, 200),
        hasAttachments: m.hasAttachments || false,
        isRead: m.isRead || false,
        mailbox: 'info@risk2solution.com',
        hoursOld: Math.round((Date.now() - new Date(m.receivedDateTime)) / 3600000)
      }));
    res.json({ emails });
  } catch (err) {
    if (err.message.includes('ErrorAccessDenied') || err.message.includes('AuthenticationError') || err.message.includes('401')) {
      res.status(403).json({ error: 'info@ mailbox access denied. Kandia needs delegate access to info@risk2solution.com' });
    } else {
      res.status(500).json({ error: err.message });
    }
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
    console.log('[Teams] Fetching chats...');
    const chatsData = await graphGet('/me/chats?$top=20&$expand=members');
    if (chatsData.error) {
      console.warn('[Teams] Graph error:', JSON.stringify(chatsData.error));
      return res.status(400).json({ error: chatsData.error.message || 'Graph API error', chats: [] });
    }
    const allChats = chatsData.value || [];
    console.log('[Teams] Found', allChats.length, 'chats');
    const chats = [];
    for (const chat of allChats.slice(0, 15)) {
      try {
        const msgs = await graphGet('/me/chats/' + chat.id + '/messages?$top=5');
        const valid = (msgs.value || []).filter(m => m.body && m.body.content && m.from && m.from.user && m.from.user.displayName);
        if (valid.length > 0) {
          // Get participant names for topic
          const members = (chat.members || []).map(m => (m.displayName || '').split(' ')[0]).filter(Boolean).join(', ');
          chats.push({
            chatId: chat.id,
            topic: chat.topic || members || 'Direct message',
            lastMessage: valid[0].body.content.replace(/<[^>]*>/g, '').substring(0, 150),
            from: valid[0].from.user.displayName,
            time: valid[0].createdDateTime
          });
        }
      } catch (e) { console.warn('[Teams] Skipping chat:', e.message); }
    }
    console.log('[Teams] Returning', chats.length, 'chats with messages');
    res.json({ chats });
  } catch (err) {
    console.error('[Teams] Fatal error:', err.message);
    res.status(500).json({ error: err.message, chats: [] });
  }
});


// ── MONDAY.COM: Get approved boards only ──
const MONDAY_BOARD_IDS = [2031906973, 2005758439]; // Project/Client Feedback + Client Projects ONLY

// ── AURORA INTEGRATION ──
const AURORA_URL      = process.env.AURORA_URL      || 'https://aurora-agent-b6f3b2fcd3a9gqct.australiaeast-01.azurewebsites.net';
const AURORA_PASSWORD = process.env.AURORA_PASSWORD || '';

function getAuroraToken() {
  if (!AURORA_PASSWORD) throw new Error('AURORA_PASSWORD not set in environment variables');
  return Buffer.from('aurora:' + AURORA_PASSWORD + ':' + Date.now()).toString('base64');
}

async function callAurora(path) {
  const token = getAuroraToken();
  const res = await fetch(AURORA_URL + path, {
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error('Aurora ' + path + ' returned ' + res.status);
  return res.json();
}

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
const MAX_CONVERSATION_MESSAGES = 20; // keep last 20 messages (~10 back-and-forth)
const MAX_OUTPUT_TOKENS = 1000;       // cap responses — increase if she gets cut off

app.options('/proxy', (req, res) => res.sendStatus(200));
app.post('/proxy', async (req, res) => {

  // Log every AI call
  const callTime = new Date().toLocaleString('en-AU', {timeZone: 'Australia/Brisbane'});
  const msgs = req.body?.messages || [];
  const lastMsg = msgs[msgs.length-1]?.content?.substring(0, 150) || 'unknown';
  const logEntry = `${callTime} | msgs:${msgs.length} | "${lastMsg}"`;
  aiCallLog.push(logEntry);
  if (aiCallLog.length > 100) aiCallLog.shift();
  try { appendFileSync(LOG_PATH, logEntry + '\n'); } catch(e) {}
  console.log('[AI CALL]', logEntry);

  try {
    const body = { ...req.body };

    // ── Trim conversation history ──
    if (body.messages && body.messages.length > MAX_CONVERSATION_MESSAGES) {
      const trimmed = body.messages.slice(-MAX_CONVERSATION_MESSAGES);
      // Always preserve the first message if it's a system-style user message
      const first = body.messages[0];
      if (first && !trimmed.includes(first)) {
        trimmed.unshift(first);
      }
      body.messages = trimmed;
      console.log(`[TRIMMED] History cut from ${msgs.length} → ${body.messages.length} messages`);
    }

    // ── Cap output tokens as safety net ──
    if (!body.max_tokens || body.max_tokens > MAX_OUTPUT_TOKENS) {
      body.max_tokens = MAX_OUTPUT_TOKENS;
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(body)
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


// ── VIEW AI CALL LOGS ──
app.get('/view-logs', requireAuth, (req, res) => {
  let fileLogs = '';
  try { fileLogs = readFileSync(LOG_PATH, 'utf8'); } catch(e) { fileLogs = 'No log file yet.'; }
  res.send('<pre style="font-family:monospace;font-size:12px;padding:20px;white-space:pre-wrap">' +
    '<h2>AI Call Log (last 100)</h2>' +
    '<p>Total in memory: ' + aiCallLog.length + '</p>' +
    '<hr>' +
    (aiCallLog.length > 0 ? aiCallLog.join('\n') : 'No AI calls recorded yet since server started.') +
    '<hr><h3>From file:</h3>' + fileLogs +
    '</pre>');
});

// ── CLEAR LOGS ──
app.get('/clear-logs', requireAuth, (req, res) => {
  aiCallLog.length = 0;
  try { writeFileSync(LOG_PATH, ''); } catch(e) {}
  res.send('Logs cleared.');
});

// ── CHECK-IN DATA STORAGE (replaces JSONBin) ──
const CHECKINS_PATH = '/home/checkins.json';

function loadCheckIns() {
  try {
    if (existsSync(CHECKINS_PATH)) {
      return JSON.parse(readFileSync(CHECKINS_PATH, 'utf8'));
    }
  } catch(e) { console.warn('CheckIns load error:', e.message); }
  return [];
}

function saveCheckIns(data) {
  writeFileSync(CHECKINS_PATH, JSON.stringify(data, null, 2));
}

app.get('/checkins/latest', (req, res) => {
  const data = loadCheckIns();
  console.log(`[Sync] /checkins/latest — returning ${data.length} check-ins`);
  if (data.length > 0) {
    console.log('[Sync] Names:', data.map(d => d.name || 'unknown').join(', '));
    console.log('[Sync] Submitted dates:', data.map(d => d.submitted || d.weekEnding || 'no date').join(', '));
  }
  res.json({ record: data });
});

app.put('/checkins/update', (req, res) => {
  try {
    const data = Array.isArray(req.body) ? req.body : [];
    saveCheckIns(data);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/checkins/submit', async (req, res) => {
  try {
    const entry = {
      ...req.body,
      submitted: req.body.submitted || new Date().toISOString(),
      receivedAt: new Date().toISOString()  // server-side receipt stamp
    };
    if (!entry.weekEnding) {
      const d = new Date(); const day = d.getDay();
      d.setDate(d.getDate() + (day === 0 ? 0 : 7 - day));
      entry.weekEnding = d.toISOString().split('T')[0];
    }
    if (!entry.name) return res.status(400).json({ error: 'Name is required' });

    // PRIMARY: save to local file
    const existing = loadCheckIns();
    const idx = existing.findIndex(e =>
      e.name && e.name.toLowerCase() === entry.name.toLowerCase() &&
      e.weekEnding === entry.weekEnding
    );
    if (idx >= 0) existing[idx] = entry;
    else existing.push(entry);
    saveCheckIns(existing);
    console.log('[CheckIn] SAVED:', entry.name, '| week ending', entry.weekEnding, '| received', entry.receivedAt);

    // BACKUP: also write to Azure Blob Storage
    try {
      const cc = await getBlobContainer();
      if (cc) {
        const safeName = (entry.name||'unknown').replace(/\s+/g, '-');
        const blobKey = 'checkins/' + entry.weekEnding + '/' + safeName + '.json';
        const bc = cc.getBlockBlobClient(blobKey);
        const blob_payload = JSON.stringify(entry);
        await bc.upload(blob_payload, blob_payload.length, { blobHTTPHeaders: { blobContentType: 'application/json' } });
        console.log('[CheckIn] BLOB BACKUP:', blobKey);
      }
    } catch(blobErr) {
      console.warn('[CheckIn] Blob backup failed (not critical):', blobErr.message);
    }

    res.json({ success: true, name: entry.name, weekEnding: entry.weekEnding });
  } catch(e) {
    console.error('[CheckIn] ERROR:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Manual check-in entry (dashboard only — requires auth)
app.post('/checkins/manual', requireAuth, async (req, res) => {
  try {
    const entry = { ...req.body, submitted: req.body.submitted || new Date().toISOString(), manualEntry: true, receivedAt: new Date().toISOString() };
    if (!entry.weekEnding) {
      const d = new Date(); const day = d.getDay();
      d.setDate(d.getDate() + (day === 0 ? 0 : 7 - day));
      entry.weekEnding = d.toISOString().split('T')[0];
    }
    const existing = loadCheckIns();
    const idx = existing.findIndex(e =>
      e.name && e.name.toLowerCase() === (entry.name||'').toLowerCase() &&
      e.weekEnding === entry.weekEnding
    );
    if (idx >= 0) existing[idx] = entry;
    else existing.push(entry);
    saveCheckIns(existing);
    console.log('[CheckIn] MANUAL ENTRY:', entry.name, '| week ending', entry.weekEnding);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ── AZURE BLOB STORAGE ──
const BLOB_CONN = process.env.BLOB_CONNECTION_STRING;
const BLOB_CONT = process.env.AZURE_STORAGE_CONTAINER || 'cinderella-data';
const DOCS_LOCAL = '/home/documents/';

async function getBlobContainer() {
  if (!BLOB_CONN) return null;
  try {
    const { BlobServiceClient } = await import('@azure/storage-blob');
    const client = BlobServiceClient.fromConnectionString(BLOB_CONN);
    const cc = client.getContainerClient(BLOB_CONT);
    await cc.createIfNotExists();
    return cc;
  } catch(e) {
    console.warn('Blob unavailable:', e.message);
    return null;
  }
}

// ── DOCUMENT LIBRARY ──
app.get('/docs/list', requireAuth, async (req, res) => {
  try {
    const cc = await getBlobContainer();
    if (cc) {
      const docs = [];
      for await (const b of cc.listBlobsFlat()) {
        docs.push({ name: b.name, size: b.properties.contentLength, uploaded: b.properties.lastModified, type: b.properties.contentType || 'application/octet-stream' });
      }
      return res.json({ docs });
    }
    // Local fallback
    if (!existsSync(DOCS_LOCAL)) return res.json({ docs: [] });
    const files = readdirSync(DOCS_LOCAL).map(f => {
      const s = statSync(pathJoin(DOCS_LOCAL, f));
      return { name: f, size: s.size, uploaded: s.mtime };
    });
    res.json({ docs: files });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/docs/upload', requireAuth, express.raw({ type: '*/*', limit: '20mb' }), async (req, res) => {
  try {
    const fname = decodeURIComponent(req.headers['x-filename'] || 'upload.bin');
    const ctype = req.headers['content-type'] || 'application/octet-stream';
    const cc = await getBlobContainer();
    if (cc) {
      const bc = cc.getBlockBlobClient(fname);
      await bc.uploadData(req.body, { blobHTTPHeaders: { blobContentType: ctype } });
    } else {
      if (!existsSync(DOCS_LOCAL)) mkdirSync(DOCS_LOCAL, { recursive: true });
      writeFileSync(pathJoin(DOCS_LOCAL, fname), req.body);
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/docs/read/:name', requireAuth, async (req, res) => {
  try {
    const fname = decodeURIComponent(req.params.name);
    const cc = await getBlobContainer();
    let buf;
    if (cc) {
      const bc = cc.getBlockBlobClient(fname);
      buf = await bc.downloadToBuffer();
    } else {
      buf = readFileSync(pathJoin(DOCS_LOCAL, fname));
    }
    if (fname.match(/\.(txt|md|csv)$/i)) {
      res.setHeader('Content-Type', 'text/plain'); res.send(buf.toString('utf8'));
    } else {
      res.json({ data: buf.toString('base64'), name: fname });
    }
  } catch(e) { res.status(404).json({ error: e.message }); }
});

app.delete('/docs/:name', requireAuth, async (req, res) => {
  try {
    const fname = decodeURIComponent(req.params.name);
    const cc = await getBlobContainer();
    if (cc) {
      await cc.getBlockBlobClient(fname).delete();
    } else {
      const fp = pathJoin(DOCS_LOCAL, fname);
      if (existsSync(fp)) unlinkSync(fp);
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── EMAIL DRAFT ──
app.post('/graph/email/draft', async (req, res) => {
  try {
    const token = await getValidToken();
    const { subject, body, to } = req.body;
    const toRecipients = (Array.isArray(to) ? to : to.split(/[;,]/).map(e => e.trim()).filter(Boolean))
      .map(email => ({ emailAddress: { address: email.trim() } }));
    const response = await fetch('https://graph.microsoft.com/v1.0/me/messages', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, body: { contentType: 'Text', content: body }, toRecipients })
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    res.json({ success: true, id: data.id });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── REPORT GENERATION ──
app.post('/generate/report', requireAuth, async (req, res) => {
  try {
    const { type, label } = req.body;
    const monthDate = new Date(); monthDate.setMonth(monthDate.getMonth() - 1);
    const monthName = monthDate.toLocaleString('en-AU', { month: 'long' });
    const yr = monthDate.getFullYear();
    let context = `REPORT: ${label||type} | MONTH: ${monthName} ${yr}\n\n`;

    // Staff check-ins for last month
    try {
      const raw = JSON.parse(readFileSync('/home/checkins.json', 'utf8') || '[]');
      const mm = monthDate.getMonth(); const yy = monthDate.getFullYear();
      const monthly = raw.filter(c => { if (!c.submitted) return false; const d = new Date(c.submitted); return d.getMonth()===mm && d.getFullYear()===yy; });
      if (monthly.length > 0) {
        context += `STAFF CHECK-INS (${monthName}):\n`;
        monthly.forEach(c => { context += `- ${c.name}: ${c.capacity}% capacity | Projects: ${c.projects||'not stated'} | Blockers: ${c.blockers||'none'} | Focus: ${c.focus||'-'}\n`; });
        context += '\n';
      }
    } catch(e) {}

    // Document library
    try {
      const cc = await getBlobContainer();
      if (cc) {
        const names = []; for await (const b of cc.listBlobsFlat()) names.push(b.name);
        if (names.length) context += `DOCUMENTS IN LIBRARY: ${names.join(', ')}\n\n`;
      }
    } catch(e) {}

    // Key emails from last month
    try {
      const token = await getValidToken();
      const since = new Date(monthDate.getFullYear(), monthDate.getMonth(), 1).toISOString();
      const until = new Date(monthDate.getFullYear(), monthDate.getMonth()+1, 1).toISOString();
      const emailData = await graphGet(`/me/messages?$top=30&$filter=receivedDateTime ge ${since} and receivedDateTime lt ${until}&$select=subject,from,importance&$orderby=receivedDateTime desc`);
      if (emailData.value?.length) {
        context += `KEY EMAILS (${monthName}):\n`;
        emailData.value.forEach(e => { context += `- ${e.from?.emailAddress?.name||'unknown'}: ${e.subject}${e.importance==='high'?' [HIGH]':''}\n`; });
        context += '\n';
      }
    } catch(e) {}

    const sysPrompt = type==='board'
      ? `You are Cinderella, executive assistant to Kandia Du Bruyn (COO) of Risk 2 Solution. Write a complete professional COO board report for ${monthName} ${yr}. Use all data provided. Be specific. No placeholder text. Format with HTML headings and bullet lists. Write every section fully.`
      : `You are Cinderella, executive assistant to Kandia Du Bruyn (COO) of Risk 2 Solution Group. Risk 2 Solution Group is Australia's most awarded integrated risk management company, providing professional services in:
- Risk Management (Presilience® programs, Business Continuity, CRO-as-a-Service, Risk Assessments)
- Security (SoCI compliance, OVA prevention, Security consulting, CSO-as-a-Service)
- Technology & Cybersecurity (Maturity Assessments, vCISO, SOC monitoring, Vulnerability Remediation)
- Training & Education (RTO #4785, Postgrad qualifications, R2S Academy eLearning, bespoke programs)
- Emergency Planning Services (EMPs, Evacuation Diagrams, Warden Training, BCP, CIM)
- Research & Events (ASRC, ISRM, PSG Conference, Presilience® Summits)
ISO Certified: 9001:2015, 45001:2018, 14001:2015, 18788:2015
20+ years | 800+ clients | 150,000+ people trained
Head Office: Murrarie QLD | Operates Australia-wide and internationally
NOTE: Medical division has been fully divested — never reference medical personnel or medical services.

Generate a complete professional ${label||type} document for ${monthName} ${yr} using the data provided. Format with HTML structure. Be comprehensive.`;

    const userMsg = type==='board'
      ? `Generate the full COO board report for ${monthName} ${yr}. Sections: 1. Executive Summary 2. People & Culture 3. Operations & Delivery 4. Client Update 5. Compliance & Risk 6. Platform & Technology 7. Next Month Priorities\n\nDATA:\n${context}`
      : `Generate a complete ${label||type} document.\n\nDATA:\n${context}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 8000, system: sysPrompt, messages: [{ role: 'user', content: userMsg }] })
    });
    const aiData = await aiRes.json();
    const reportContent = aiData.content?.[0]?.text || 'Unable to generate report.';

    const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head><meta charset="utf-8"><title>${label||type}</title>
<style>
body{font-family:Arial,sans-serif;font-size:11pt;margin:2cm 2.5cm;line-height:1.5}
h1{font-size:18pt;color:#1F4E79;border-bottom:2pt solid #1F4E79;padding-bottom:4pt}
h2{font-size:14pt;color:#2E75B6;margin-top:16pt}
h3{font-size:12pt;color:#2E75B6}
.cover{text-align:center;margin-bottom:40pt;padding:20pt;border:1pt solid #2E75B6}
ul,ol{margin:4pt 0;padding-left:20pt}li{margin-bottom:3pt}
table{border-collapse:collapse;width:100%}td,th{border:.5pt solid #CCC;padding:4pt 8pt}
th{background:#EEF3F9;font-weight:bold}
</style></head>
<body>
<div class="cover">
<h1>${label||type}</h1>
<p style="font-size:13pt;color:#555">Risk 2 Solution</p>
<p style="font-size:10pt;color:#888">Prepared by Kandia Du Bruyn, COO &nbsp;|&nbsp; ${monthName} ${yr}</p>
</div>
${reportContent}
</body></html>`;

    const filename = `${(label||type).replace(/[^a-z0-9]/gi,'-')}-${monthName}-${yr}.doc`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/msword');
    res.send(docHtml);
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── OPEN ACTIONS TRACKER ──
const ACTIONS_PATH = '/home/openactions.json';
function loadActions() {
  try { return JSON.parse(readFileSync(ACTIONS_PATH,'utf8')||'[]'); } catch(e) { return []; }
}
function saveActions(data) {
  writeFileSync(ACTIONS_PATH, JSON.stringify(data, null, 2));
}

app.get('/openactions', requireAuth, (req, res) => {
  res.json({ actions: loadActions() });
});

app.post('/openactions', requireAuth, (req, res) => {
  try {
    const actions = loadActions();
    const action = {
      id: Date.now(),
      title: req.body.title || 'Untitled action',
      source: req.body.source || '',
      urgency: req.body.urgency || 'This week',
      detail: req.body.detail || '',
      deadline: req.body.deadline || null,
      addedAt: new Date().toISOString(),
      status: 'open',
      type: req.body.type || 'manual',
      emailFrom: req.body.emailFrom || null,
      emailSubject: req.body.emailSubject || null
    };
    actions.unshift(action);
    saveActions(actions);
    console.log('[Actions] Added:', action.title);
    res.json({ success: true, action });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/openactions/:id', requireAuth, (req, res) => {
  try {
    const actions = loadActions();
    const idx = actions.findIndex(a => String(a.id) === String(req.params.id));
    if (idx < 0) return res.status(404).json({ error: 'Not found' });
    actions[idx] = { ...actions[idx], ...req.body, id: actions[idx].id };
    if (req.body.status && req.body.status !== 'open') actions[idx].resolvedAt = new Date().toISOString();
    saveActions(actions);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/openactions/:id', requireAuth, (req, res) => {
  try {
    const actions = loadActions().filter(a => String(a.id) !== String(req.params.id));
    saveActions(actions);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── BOARD REPORT SYSTEM ──
const BOARD_STATE_PATH = '/home/board-report-state.json';
// Kandia's email is pulled from the authenticated M365 account — no env var needed
let KANDIA_EMAIL = null;
async function getKandiaEmail() {
  if (KANDIA_EMAIL) return KANDIA_EMAIL;
  try {
    const me = await graphGet('/me?$select=mail,userPrincipalName');
    KANDIA_EMAIL = me.mail || me.userPrincipalName || 'kandia@risk2solution.com';
    console.log('[Auth] Kandia email resolved:', KANDIA_EMAIL);
  } catch(e) { KANDIA_EMAIL = 'kandia@risk2solution.com'; }
  return KANDIA_EMAIL;
}

function loadBoardState() {
  try { return JSON.parse(readFileSync(BOARD_STATE_PATH,'utf8')||'{}'); } catch(e) { return {}; }
}
function saveBoardState(s) {
  try { writeFileSync(BOARD_STATE_PATH, JSON.stringify(s,null,2)); } catch(e) {}
}

async function checkBoardMeetingSchedule() {
  if (!tokenStore.access_token) return;

  const now = new Date();

  // AUTO-CLEAR: if the last notified meeting has passed by more than 2 days, clear state
  // so the display resets and next month's cycle can begin
  const state = loadBoardState();
  if (state.lastMeetingDate) {
    const lastMeeting = new Date(state.lastMeetingDate);
    const daysSinceMeeting = (now - lastMeeting) / (24*60*60*1000);
    if (daysSinceMeeting > 2) {
      console.log('[BoardReport] Last meeting was', Math.round(daysSinceMeeting), 'days ago — clearing state for next cycle');
      state.notifiedMonth = null;
      state.lastReportPath = null;
      state.lastReportMeeting = null;
      state.lastReportDate = null;
      state.lastSentDate = null;
      state.lastMeetingDate = null;
      saveBoardState(state);
    }
  }

  const dayOfWeek = now.toLocaleDateString('en-AU',{timeZone:'Australia/Brisbane',weekday:'long'});
  if (dayOfWeek !== 'Thursday') return;

  // Reload state after potential clear above
  const freshState = loadBoardState();

  // Block only if sent successfully TODAY
  const alreadySentToday = freshState.lastSentDate &&
    new Date(freshState.lastSentDate).toLocaleDateString('en-AU',{timeZone:'Australia/Brisbane'}) ===
    now.toLocaleDateString('en-AU',{timeZone:'Australia/Brisbane'});
  if (alreadySentToday) { console.log('[BoardReport] Already sent successfully today, skipping'); return; }

  console.log('[BoardReport] Thursday — scanning calendar for board meetings...');
  try {
    // Look ahead 7 days only — Thursday trigger catches next week's meeting, NOT the week after
    // e.g. Thursday 7 Aug catches Tuesday 11 Aug (4 days away). Thursday 31 Jul does NOT catch Tue 11 Aug (11 days away).
    const from = now.toISOString();
    const to = new Date(now.getTime() + 7*24*60*60*1000).toISOString();
    const cal = await graphGet(`/me/calendarView?startDateTime=${from}&endDateTime=${to}&$select=subject,start,end&$top=20`);
    const boardMeeting = (cal.value||[]).find(e => {
      if (!e.subject) return false;
      const s = e.subject.toLowerCase();
      return s.includes('board');  // Simple: any calendar event with "board" in the title
    });
    if (!boardMeeting) { console.log('[BoardReport] No board meeting found in next 7 days (correct — will check again next Thursday)'); return; }

    const meetingDate = new Date(boardMeeting.start.dateTime || boardMeeting.start.date);
    const daysUntil = Math.round((meetingDate - now) / (24*60*60*1000));
    const monthKey = meetingDate.toISOString().substring(0,7);
    console.log('[BoardReport] Found:', boardMeeting.subject, '— in', daysUntil, 'days');

    // Safety check — meeting must be within 7 days (next week from Thursday)
    if (daysUntil > 7) {
      console.log('[BoardReport] Meeting is', daysUntil, 'days out — too far ahead. Will trigger on the Thursday closer to the meeting.');
      return;
    }
    if (daysUntil < 1) {
      console.log('[BoardReport] Meeting has already passed — skipping');
      return;
    }

    // Don't re-send if already notified — UNLESS the last send was premature (sent >7 days before meeting)
    if (freshState.notifiedMonth === monthKey) {
      const lastSent = freshState.lastSentDate ? new Date(freshState.lastSentDate) : null;
      const daysBetweenSendAndMeeting = lastSent ? (meetingDate - lastSent) / (24*60*60*1000) : 0;
      if (daysBetweenSendAndMeeting > 7) {
        console.log('[BoardReport] Previous send was premature (' + Math.round(daysBetweenSendAndMeeting) + ' days before meeting) — re-sending on correct Thursday');
        // Allow re-send — fall through
      } else {
        console.log('[BoardReport] Already notified for', monthKey, '— skipping');
        return;
      }
    }

    // Generate and send
    console.log('[BoardReport] Generating report...');
    const reportPath = await generateBoardReport(meetingDate, boardMeeting.subject);
    await sendBoardReportNotification(boardMeeting.subject, meetingDate, daysUntil, reportPath);

    // Only save state after successful send
    const newState = loadBoardState();
    newState.notifiedMonth = monthKey;
    newState.lastReportPath = reportPath;
    newState.lastReportMeeting = boardMeeting.subject;
    newState.lastReportDate = now.toISOString();
    newState.lastSentDate = now.toISOString();
    newState.lastMeetingDate = meetingDate.toISOString(); // Save meeting date for auto-clear
    saveBoardState(newState);
    console.log('[BoardReport] ✅ Done — report generated and emailed to Kandia');
  } catch(e) {
    console.error('[BoardReport] Error (will retry next think loop):', e.message);
    // Don't save state — let it retry next time the think loop runs
  }
}

async function generateBoardReport(meetingDate, meetingSubject) {
  const reportMonth = new Date(meetingDate);
  reportMonth.setMonth(reportMonth.getMonth() - 1);
  const monthName = reportMonth.toLocaleString('en-AU',{month:'long'});
  const yr = reportMonth.getFullYear();
  const mm = reportMonth.getMonth();
  const yy = reportMonth.getFullYear();

  let context = 'BOARD REPORT CONTEXT\n===================\n\n';

  // 1. ALL EMAILS — PRIORITY FIRST — broad fetch, rich content, prioritised first in context
  try {
    // Fetch from start of report month to now (catches Diane's month-end emails sent after month close)
    const since = new Date(yy, mm, 1).toISOString();
    const nowStr = new Date().toISOString();
    // Use bodyPreview (clean 255-char text, no HTML stripping needed) + full body for key emails
    const emailData = await graphGet(
      `/me/messages?$top=150&$filter=receivedDateTime ge ${since} and receivedDateTime lt ${nowStr}` +
      `&$select=subject,from,bodyPreview,body,importance,receivedDateTime&$orderby=receivedDateTime desc`
    );
    const emails = emailData.value || [];
    console.log('[BoardReport] Fetched', emails.length, 'emails from', monthName);

    // CATEGORY 1 — Finance emails (Diane or finance keywords) — get full body content
    const financeEmails = emails.filter(e => {
      const from = (e.from?.emailAddress?.name||'').toLowerCase();
      const subj = (e.subject||'').toLowerCase();
      // Exclude Cinderella's own board report notification emails
      if (subj.includes('board report ready')) return false;
      // Prioritise emails FROM Diane/Kruger - she sends the monthly P&L
      if (from.includes('diane') || from.includes('kruger')) return true;
      // Tight subject keywords only - avoid noise like 'report' or 'monthly'
      return !!subj.match(/payroll|month.?end|year.?end|p&l|profit.?loss|revenue|budget|reconcil|fy2|fy 2|year to date|ytd|cash flow|forecast/i);
    });
    console.log('[BoardReport] Finance emails found:', financeEmails.length, financeEmails.map(e=>e.subject).join(' | '));

    // Extract dollar figures from finance email previews as a quick-capture fallback
    const financeFigures = [];
    financeEmails.forEach(e => {
      const text = (e.bodyPreview || '') + ' ' + (e.subject || '');
      const dollarMatches = text.match(/\$[\d,]+\.?\d{0,2}/g) || [];
      const positiveMatch = text.match(/positive[^$]*\$[\d,]+|closed.*\$[\d,]+|result.*\$[\d,]+/i);
      if (dollarMatches.length > 0 || positiveMatch) {
        financeFigures.push({
          from: e.from?.emailAddress?.name,
          subject: e.subject,
          date: e.receivedDateTime?.substring(0,10),
          figures: dollarMatches.slice(0,5),
          preview: e.bodyPreview?.substring(0,300)
        });
      }
    });
    if (financeFigures.length > 0) {
      context += 'KEY FINANCIAL FIGURES EXTRACTED FROM EMAILS:\n';
      financeFigures.forEach(f => {
        context += `${f.date} — ${f.from}: "${f.subject}" | Figures: ${f.figures.join(', ')}\n`;
        context += `  Preview: ${f.preview}\n\n`;
      });
    }

    if (financeEmails.length > 0) {
      context += 'FINANCE EMAILS — ' + monthName + ' (primary source for financial overview):\n';
      financeEmails.slice(0,15).forEach(e => {
        // Use bodyPreview first (clean text), then fall back to stripping body HTML
        const cleanPreview = e.bodyPreview || '';
        const htmlBody = e.body?.content || '';
        const bodyText = htmlBody
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
          .replace(/\s+/g, ' ').trim();
        // Combine preview + body — preview is cleaner, body may have more detail
        const combined = (cleanPreview + ' ' + bodyText.substring(0, 600)).trim().substring(0, 900);
        const date = e.receivedDateTime ? new Date(e.receivedDateTime).toLocaleDateString('en-AU',{day:'numeric',month:'short',year:'numeric'}) : '';
        context += `FROM: ${e.from?.emailAddress?.name||'?'} (${date})\nSUBJECT: ${e.subject}\nCONTENT: ${combined}\n\n`;
      });
    }

    // CATEGORY 2 — Strategic/operational emails (DISP, EMDG, grants, compliance, legal, staff events, conference, tenders)
    const STRATEGIC_KEYWORDS = [
      'disp','clearance','security clearance','emdg','grant','tender','conference','staff event',
      'asqa','rto','accreditation','renewal','compliance','audit','legal','court','tribunal',
      'auruba','immigration','visa','contract','partnership','proposal','onboarding',
      'workers comp','payroll tax','bas','gst','annual leave','recruitment','hiring',
      'resign','termination','performance','incident','injury','welfare',
      'psg','pss','iop','eps','presilience','risk management','emergency planning'
    ];
    const strategicEmails = emails.filter(e => {
      if (financeEmails.includes(e)) return false;
      const subj = (e.subject||'').toLowerCase();
      const preview = (e.bodyPreview||'').toLowerCase();
      return STRATEGIC_KEYWORDS.some(k => subj.includes(k) || preview.includes(k)) || e.importance === 'high';
    });
    if (strategicEmails.length > 0) {
      context += 'STRATEGIC & OPERATIONAL EMAILS — ' + monthName + ':\n';
      strategicEmails.slice(0,30).forEach(e => {
        const htmlBody = e.body?.content || '';
        const bodyText = htmlBody
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ').trim();
        const bodyPreview = bodyText.substring(0, 400);
        const date = e.receivedDateTime ? new Date(e.receivedDateTime).toLocaleDateString('en-AU',{day:'numeric',month:'short'}) : '';
        context += `FROM: ${e.from?.emailAddress?.name||'?'} (${date}) — ${e.subject}\n${bodyPreview}\n\n`;
      });
    }

    // CATEGORY 3 — All other emails (subjects only for breadth)
    const otherEmails = emails.filter(e => !financeEmails.includes(e) && !strategicEmails.includes(e)).slice(0,30);
    if (otherEmails.length > 0) {
      context += 'OTHER EMAILS — ' + monthName + ' (subjects):\n';
      otherEmails.forEach(e => {
        context += `- ${e.from?.emailAddress?.name||'?'}: ${e.subject}${e.importance==='high'?' [HIGH]':''}\n`;
      });
      context += '\n';
    }
  } catch(e) { console.warn('[BoardReport] Email fetch:', e.message); }

  // 2. Staff check-ins for the month
  try {
    const raw = JSON.parse(readFileSync('/home/checkins.json','utf8')||'[]');
    const monthly = raw.filter(c => {
      if (!c.submitted) return false;
      const d = new Date(c.submitted);
      return d.getMonth()===mm && d.getFullYear()===yy;
    });
    if (monthly.length > 0) {
      context += 'STAFF CHECK-INS ('+monthName+' — '+monthly.length+' submissions):\n';
      monthly.forEach(c => {
        context += '- '+c.name+' ('+c.role+'): capacity '+c.capacity+'%';
        if (c.capacityNext) context += ', next week forecast '+c.capacityNext+'%';
        if (c.trend) context += ', trend: '+c.trend;
        if (c.projects) context += '\n  Projects: '+c.projects;
        if (c.blockers && c.blockers.toLowerCase() !== 'none') context += '\n  Blockers: '+c.blockers;
        if (c.skills) context += '\n  Skills applied: '+c.skills;
        context += '\n';
      });
      context += '\n';
    }
  } catch(e) {}

  // Hardcoded financial data removed — report now uses live email data only


  // 3. Document library - read actual content of past board reports + list other docs
  try {
    const cc = await getBlobContainer();
    if (cc) {
      const docs = [];
      const pastReports = [];

      for await (const b of cc.listBlobsFlat()) {
        if (b.name.toLowerCase().match(/board.?report|board.?pack/)) {
          pastReports.push({ name: b.name, size: b.properties.contentLength });
        } else {
          docs.push(b.name);
        }
      }

      // Read the actual content of up to 3 most recent past board reports
      if (pastReports.length > 0) {
        // Sort by name descending (filenames include year-month so newest sorts last alphabetically)
        pastReports.sort((a, b) => b.name.localeCompare(a.name));
        const reportsToRead = pastReports.slice(0, 3);
        context += 'PREVIOUS BOARD REPORTS (content extracted for carry-forward review):\n';
        context += 'Reports found: ' + pastReports.map(r => r.name).join(', ') + '\n\n';

        for (const report of reportsToRead) {
          // Skip the current month's report to avoid circular reference
          const reportMonth = report.name.match(/(\d{4}-\d{2})/)?.[1];
          const currentMonthKey = yr + '-' + String(mm+1).padStart(2,'0');
          if (reportMonth === currentMonthKey) {
            console.log('[BoardReport] Skipping current month report:', report.name);
            continue;
          }
          try {
            const bc = cc.getBlockBlobClient(report.name);
            const buf = await bc.downloadToBuffer();
            const raw = buf.toString('utf8');
            let text = raw
              .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
              .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
              .replace(/<[^>]+>/g, ' ')
              .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
              .replace(/\s+/g, ' ').trim();
            // Extract only carry-forward sections — items for board, compliance, open actions
            // Do NOT pass financial figures from old reports — they poison the current report
            const carryForwardMarkers = [
              'items for board', 'board decision', 'board awareness', 'carry forward',
              'compliance', 'open action', 'outstanding', 'pending', 'follow up',
              'disp', 'emdg', 'asqa', 'rto', 'workers comp', 'legal', 'tender'
            ];
            const sentences = text.split(/\.\s+/);
            const relevant = sentences.filter(s => {
              const sl = s.toLowerCase();
              return carryForwardMarkers.some(m => sl.includes(m));
            }).join('. ');
            const carryText = (relevant || text).substring(0, 1500);
            context += 'CARRY-FORWARD FROM ' + report.name + ' (open items only — do NOT reuse financial figures from this report):\n';
            context += carryText + '\n\n';
            console.log('[BoardReport] Read past report for carry-forward:', report.name, '(' + carryText.length + ' chars)');
          } catch(readErr) {
            console.warn('[BoardReport] Could not read', report.name, ':', readErr.message);
          }
        }
      } else {
        context += 'PAST BOARD REPORTS: None found in document library.\n\n';
      }

      if (docs.length > 0) context += 'OTHER DOCUMENTS IN LIBRARY: ' + docs.join(', ') + '\n\n';
    }
  } catch(e) { console.warn('[BoardReport] Doc library read error:', e.message); }

  // 3b. Aurora project data
  try {
    const aurData = await callAurora('/api/projects');
    const projects = aurData.projects || [];
    const PHASES = ['Enquiry','Proposal','Active','Review','Close-out'];
    const active = projects.filter(p => p.phase >= 1 && p.phase <= 3);
    if (active.length > 0) {
      context += 'ACTIVE PROJECTS (from Aurora):\n';
      for (const p of active.slice(0, 10)) {
        let invTotal = 0, invPaid = 0;
        try {
          const inv = await callAurora('/api/projects/' + p.id + '/invoices');
          (inv.invoices||[]).forEach(i => { invTotal += parseFloat(i.amount||0); if(i.paid) invPaid += parseFloat(i.amount||0); });
        } catch(e) {}
        let overdueCount = 0;
        try {
          const del = await callAurora('/api/projects/' + p.id + '/deliverables');
          overdueCount = (del.deliverables||[]).filter(d => d.status==='Overdue' || (d.dueDate && new Date(d.dueDate)<new Date() && d.status!=='Complete')).length;
        } catch(e) {}
        context += '- ' + p.clientName + ' | Phase: ' + (PHASES[p.phase]||'?') + ' | Consultant: ' + (p.consultant||'TBC');
        if (invTotal > 0) context += ' | Invoiced: $' + invTotal.toFixed(2) + ' Paid: $' + invPaid.toFixed(2) + ' Outstanding: $' + (invTotal-invPaid).toFixed(2);
        if (overdueCount > 0) context += ' | ⚠ ' + overdueCount + ' overdue deliverable(s)';
        if (p.dueDate) context += ' | Due: ' + p.dueDate;
        context += '\n';
      }
      context += '\n';
    }
  } catch(e) { console.warn('[BoardReport] Aurora data:', e.message); }

  // 4. Monday.com client projects
  try {
    const monday = await fetch('https://api.monday.com/v2', {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':process.env.MONDAY_API_KEY},
      body:JSON.stringify({query:'{ boards(ids:[2031906973,2005758439,2005747804]) { name items_page { items { name column_values { id text } } } } }'})
    });
    const md = await monday.json();
    const boards = md.data?.boards || [];
    if (boards.length > 0) {
      context += 'CLIENT PROJECTS (Monday.com):\n';
      boards.forEach(b => {
        const items = b.items_page?.items || [];
        items.slice(0,8).forEach(item => {
          const status = (item.column_values||[]).find(c=>c.id.includes('color')||c.id.includes('status'));
          context += '- '+item.name+(status?' ['+status.text+']':'')+'\n';
        });
      });
      context += '\n';
    }
  } catch(e) {}

  // 5. Open actions tracker
  try {
    const actions = loadActions();
    const open = actions.filter(a => a.status === 'open');
    if (open.length > 0) {
      context += 'OPEN ACTION ITEMS (from tracker):\n';
      open.forEach(a => context += '- ['+a.urgency+'] '+a.title+' (from: '+a.source+')'+'\n');
      context += '\n';
    }
  } catch(e) {}

  // 6. CALENDAR EVENTS — significant items from Kandia's calendar (past 45 days + upcoming 60 days)
  try {
    const calFrom = new Date(now.getFullYear(), now.getMonth()-1, 1).toISOString();
    const calTo   = new Date(now.getFullYear(), now.getMonth()+2, 0).toISOString();
    const calData = await graphGet(`/me/calendarView?startDateTime=${calFrom}&endDateTime=${calTo}&$select=subject,start,end,bodyPreview&$top=100&$orderby=start/dateTime`);
    const SIG_KEYWORDS = ['ospa','asqa','disp','tender','board','submission','renewal','audit','review','accreditation','training','client','meeting','grant','emdg','compliance','certification','psg','payroll','clearance','hr','legal','court','tribunal','application','deadline','milestone'];
    const significant = (calData.value||[]).filter(e => {
      const s = (e.subject||'').toLowerCase();
      return SIG_KEYWORDS.some(k => s.includes(k));
    });
    if (significant.length > 0) {
      context += 'CALENDAR — SIGNIFICANT EVENTS (past month to next 2 months):\n';
      significant.forEach(e => {
        const d = new Date(e.start.dateTime||e.start.date);
        const isPast = d < now;
        context += (isPast ? '[PAST] ' : '[UPCOMING] ') + d.toLocaleDateString('en-AU',{day:'numeric',month:'short',year:'numeric'}) + ' — ' + e.subject + '\n';
        if (e.bodyPreview && e.bodyPreview.length > 20) context += '  ' + e.bodyPreview.substring(0,120).replace(/\n/g,' ') + '\n';
      });
      context += '\n';
    }
  } catch(e) { console.warn('[BoardReport] Calendar fetch:', e.message); }

  // 7. CLOCKIFY — staff hours vs capacity for the current month
  try {
    if (CLOCKIFY_API_KEY) {
      const workspaces = await callClockify('/workspaces');
      const ws = (workspaces||[]).find(w => w.name === 'Risk 2 Solution') || workspaces[0];
      if (ws) {
        const users = await callClockify('/workspaces/' + ws.id + '/users?page-size=50');
        const monthStart = new Date(yy, mm, 1).toISOString();
        const monthEndDt = new Date(yy, mm+1, 0, 23, 59, 59).toISOString();
        let clockifyCtx = 'CLOCKIFY — TIME TRACKING VS CAPACITY ('+monthName+'):\n';
        let hasData = false;

        // Load check-ins for cross-reference
        let allCheckIns = [];
        try { allCheckIns = JSON.parse(readFileSync('/home/checkins.json','utf8')||'[]'); } catch(e) {}
        const monthCheckIns = allCheckIns.filter(c => {
          if (!c.submitted) return false;
          const d = new Date(c.submitted);
          return d.getFullYear() === yy && d.getMonth() === mm;
        });

        for (const user of users) {
          const match = CLOCKIFY_STAFF_MAP.find(m => {
            const name = (user.name||'').toLowerCase();
            const email = (user.email||'').toLowerCase();
            return name.includes(m.clockify.toLowerCase()) || email.includes(m.clockify.toLowerCase());
          });
          if (!match) continue;
          try {
            const entries = await callClockify('/workspaces/'+ws.id+'/user/'+user.id+'/time-entries?start='+encodeURIComponent(monthStart)+'&end='+encodeURIComponent(monthEndDt)+'&page-size=500');
            let totalHrs = 0;
            (entries||[]).forEach(e => {
              if (e.timeInterval?.duration) totalHrs += parseDuration(e.timeInterval.duration);
              else if (e.timeInterval?.start && e.timeInterval?.end)
                totalHrs += (new Date(e.timeInterval.end) - new Date(e.timeInterval.start)) / 3600000;
            });
            totalHrs = Math.round(totalHrs * 10) / 10;
            // Find their avg capacity from check-ins this month
            const personCheckIns = monthCheckIns.filter(c => (c.name||'').toLowerCase().includes(match.checkIn.split(' ')[0].toLowerCase()));
            const avgCap = personCheckIns.length > 0 ? Math.round(personCheckIns.reduce((s,c) => s + (c.capacity||0), 0) / personCheckIns.length) : null;
            const impliedHrs = avgCap !== null ? Math.round((avgCap/100)*37.5*4.3*10)/10 : null; // monthly
            clockifyCtx += '- ' + match.checkIn + ': ' + totalHrs + 'h logged this month';
            if (avgCap !== null) clockifyCtx += ' | avg check-in capacity: ' + avgCap + '%' + (impliedHrs ? ' (~' + impliedHrs + 'h implied)' : '');
            if (impliedHrs && totalHrs > 0) {
              const gap = totalHrs - impliedHrs;
              if (gap > 20) clockifyCtx += ' | ⚠ OVER capacity (possible burnout)';
              else if (gap < -20 && avgCap > 50) clockifyCtx += ' | ⚠ Under hours vs reported capacity';
            }
            clockifyCtx += '\n';
            hasData = true;
          } catch(e) {}
        }
        if (hasData) { context += clockifyCtx + '\n'; }
      }
    }
  } catch(e) { console.warn('[BoardReport] Clockify context:', e.message); }

  // 8. TEAMS MESSAGES — recent significant discussions
  try {
    const chats = await graphGet('/me/chats?$top=20&$expand=members');
    let teamsCtx = '';
    let chatCount = 0;
    for (const chat of (chats.value||[]).slice(0, 10)) {
      try {
        const msgs = await graphGet('/me/chats/'+chat.id+'/messages?$top=10&$orderby=createdDateTime desc');
        const recent = (msgs.value||[]).filter(m => {
          if (!m.createdDateTime) return false;
          const d = new Date(m.createdDateTime);
          const cutoff = new Date(now.getTime() - 45*24*60*60*1000);
          return d >= cutoff;
        });
        if (recent.length > 0) {
          const chatName = chat.topic || (chat.members||[]).filter(m => !(m.displayName||'').includes('Kandia')).map(m => m.displayName).join(', ');
          recent.slice(0,3).forEach(m => {
            const body = (m.body?.content||'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().substring(0,150);
            if (body.length > 20) teamsCtx += '- ['+chatName+'] '+(m.from?.user?.displayName||'?')+': '+body+'\n';
          });
          chatCount++;
        }
      } catch(e) {}
      if (chatCount >= 5) break;
    }
    if (teamsCtx) context += 'TEAMS MESSAGES (recent):\n' + teamsCtx + '\n';
  } catch(e) { console.warn('[BoardReport] Teams context:', e.message); }

  // Generate comprehensive report — AI returns JSON, server builds HTML
  const NAVY  = '#1B3A6B';
  const GREEN = '#1E8449';
  const RED   = '#C0392B';
  const AMBER = '#D68910';

  // Truncate context before building prompt to avoid token limit
  const MAX_CTX = 40000;
  if (context.length > MAX_CTX) {
    console.warn('[BoardReport] Context truncated from', context.length, 'to', MAX_CTX, 'chars');
    context = context.substring(0, MAX_CTX) + '\n[Context truncated]';
  }


  const sysP = `You are Cinderella, executive assistant to Kandia Du Bruyn, COO at Risk 2 Solution Group.
Generate a COO Board Paper for ${monthName} ${yr}. Output ONLY valid JSON - no markdown, no backticks, no extra text.

JSON structure required:
{"executiveSummary":"string","financialTableRows":[{"period":"","result":"","resultClass":"pos or neg","keyDriver":""}],"financeNote":"string","financialAnalysis":"string","peopleIntro":"string","peopleRows":[{"name":"","role":"","capacity":"","hours":"","status":"stable or monitor or at-limit or blocker","note":""}],"clientIntro":"string","clientRows":[{"client":"","status":""}],"newBusiness":["string"],"complianceItems":["string"],"boardItems":[{"item":"","type":"For Noting or For Awareness or For Decision","action":""}]}

DEPTH AND SPECIFICITY - CRITICAL. Every field must contain specific facts, names, figures, and dates. Generic filler is not acceptable.

FINANCIAL:
- Use ONLY figures from FINANCE EMAILS and KEY FINANCIAL FIGURES EXTRACTED in context
- July 2026: Diane Kruger confirmed in "P&L July 2026" (3 Aug 2026): July closed positive at $17,209.41 - use this exact figure
- Do NOT use $37,038.11 (FY25/26 year-end) or -$62,000 (old forecast) for July results
- Show July 2026 actual, FY26/27 YTD if available, and forward outlook
- Note: Dave Cohen requested Diane prepare a mini P&L per project (cost and opex vs revenue to calculate net profit per project) - in progress, figures in Excel attachment; board should be aware this reporting framework is being developed
- financialAnalysis: specific commentary on the July result vs the -$62,000 forecast, what drove it, BD pipeline status

PEOPLE:
- Cross-reference check-in capacity % with monthly Clockify hours (capacity% x 37.5h x 4.3 weeks = implied monthly hours)
- Be specific: use actual project names from check-ins, actual blocker details
- Note: Dylan Finigan accepted offer as Business Development Associate (5 Aug 2026), onboarding in progress via Diane Kruger and Janita Zhang
- Do not write generic notes

COMPLIANCE - include ALL of:
- DISP Application: Kandia submitted documents to Auruba/Defence 5 Aug 2026, Paul Johnston provided SRA Template (37 risk exposures), Dave Cohen baseline clearance application via myClearance - 10 business day deadline or Defence may withdraw
- EMDG Grant: MR-001-EMDG-10019821 - CEO action required from Dave Cohen
- ISO Audit 2026: underway with external auditor Craig (Global ISO Services), Diane and team preparing documentation
- Any ASQA/RTO matters if in context

CLIENT DELIVERY:
- Use actual project names from Aurora, BHP project update forwarded via info@
- Charters Towers Regional Council VendorPanel tender PR000135 (Training Services)
- Note any overdue deliverables specifically

BOARD ITEMS - genuinely board-level only (strategic, governance, financial, compliance):
- July financial result, EMDG CEO action, DISP clearance progress, new BD hire, mini P&L framework, ISO audit
- NOT: individual invoice queries, routine payables, scheduling

EXECUTIVE SUMMARY: 3-4 sentences covering July result ($17,209.41), DISP progress, new BD hire, primary challenge/decision.

No em dashes. No underlines. Use hyphen (-) instead of dash.`;

  const usrP = `Generate the board paper JSON for ${monthName} ${yr}. Meeting: ${meetingSubject} on ${meetingDate.toLocaleDateString("en-AU",{weekday:"long",day:"numeric",month:"long",year:"numeric"})}.

DATA:
${context}`;

  console.log('[BoardReport] Calling Claude API — context:', context.length, 'chars');
  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method:'POST',
    headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
    body:JSON.stringify({model:'claude-sonnet-4-6',max_tokens:6000,system:sysP,messages:[{role:'user',content:usrP}]})
  });
  if (!aiRes.ok) {
    const errText = await aiRes.text();
    console.error('[BoardReport] API HTTP error', aiRes.status, ':', errText.substring(0,500));
    throw new Error('Claude API returned ' + aiRes.status + ': ' + errText.substring(0,200));
  }
  const aiData = await aiRes.json();
  console.log('[BoardReport] API response stop_reason:', aiData.stop_reason, '| usage:', JSON.stringify(aiData.usage));

  let sections = {};
  try {
    let raw = (aiData.content||[]).map(c=>c.text||'').join('');
    console.log('[BoardReport] Raw AI response (first 500):', raw.substring(0,500));
    // Strip any markdown wrappers
    raw = raw.replace(/^```json\s*/,'').replace(/^```\s*/,'').replace(/\s*```$/,'').trim();
    // Find JSON object if there's extra text around it
    const jsonMatch = raw.match(/(\{[\s\S]*\})/);
    if (jsonMatch) raw = jsonMatch[1];
    sections = JSON.parse(raw);
    console.log('[BoardReport] JSON parsed successfully — sections:', Object.keys(sections).join(', '));
  } catch(e) {
    const rawContent = (aiData.content||[]).map(c=>c.text||'').join('').substring(0,1000);
    console.error('[BoardReport] JSON parse failed:', e.message, '\nRaw content:', rawContent);
    // Re-throw so the outer catch in checkBoardMeetingSchedule logs it and retries
    throw new Error('Board report JSON parse failed — check Azure logs for raw AI response. Error: ' + e.message);
  }

  // ── BUILD HTML SERVER-SIDE WITH CORRECT TEMPLATE COLORS ──
  const STYLE = `<style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:Calibri,Arial,sans-serif;font-size:11pt;color:#1A1A1A;background:#fff;line-height:1.5}
    .page{max-width:800px;margin:0 auto;padding:28px 32px}
    h2{color:${NAVY};font-size:13pt;border-bottom:1.5px solid #C7D8E8;padding-bottom:5px;margin:20px 0 10px;font-weight:600}
    table{width:100%;border-collapse:collapse;font-size:9.5pt;margin-bottom:12px}
    th{background:${NAVY};color:#fff;padding:7px 10px;text-align:left;font-weight:600}
    td{padding:7px 10px;border:0.5px solid #d0d0d0;vertical-align:top}
    tr.alt{background:#F5F8FC}
    .pos{color:${GREEN};font-weight:700}
    .neg{color:${RED};font-weight:700}
    .amb{color:${AMBER};font-weight:700}
    .coo-box{background:#EEF3FB;border-left:3px solid ${NAVY};padding:10px 14px;margin:10px 0 16px;font-size:9.5pt;line-height:1.6}
    .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:8.5pt;font-weight:600;white-space:nowrap}
    .stable{background:#E8F5F1;color:#1E5C3A}
    .monitor{background:#FFF3E0;color:#7A3D00}
    .at-limit{background:#FFEBEE;color:#8F0000}
    .blocker{background:#FFCDD2;color:#6B0000}
    ul{padding-left:18px;font-size:9.5pt;line-height:1.8}
    p{font-size:10pt;line-height:1.6;margin-bottom:10px}
    .meta td{border:0.5px solid #C7D8E8;background:#F5F8FC;font-size:9.5pt;padding:6px 10px}
    .kpi-row{display:flex;gap:12px;margin-bottom:14px}
    .kpi{flex:1;border-radius:4px;padding:12px;text-align:center}
    .kpi-p{border:1.5px solid #B2D4C0}
    .kpi-n{border:1.5px solid #E8BBBB}
    .kpi-label{font-size:9pt;color:#666;margin-bottom:4px}
    .kpi-val-p{font-size:18pt;font-weight:700;color:${GREEN}}
    .kpi-val-n{font-size:18pt;font-weight:700;color:${RED}}
    .kpi-sub{font-size:9pt;color:#888}
  </style>`;

  const meetDateStr = meetingDate.toLocaleDateString('en-AU',{weekday:'long',day:'numeric',month:'long',year:'numeric'});

  // Cover
  const COVER = `
  <div style="border-bottom:2.5px solid ${NAVY};padding-bottom:16px;margin-bottom:18px">
    <div style="font-size:22pt;font-weight:700;color:${NAVY}">COO Board Report</div>
    <div style="font-size:13pt;color:#444;margin-top:4px">Risk 2 Solution</div>
    <div style="font-size:11pt;color:#666;margin-top:2px">${monthName} ${yr}</div>
    <div style="margin-top:10px;font-size:10pt;color:#444">Kandia Du Bruyn, COO<br>For: Board Meeting<br>Meeting date: ${meetDateStr}</div>
  </div>
  <table class="meta"><tr>
    <td><strong>Period:</strong> ${monthName} ${yr}</td>
    <td><strong>Prepared by:</strong> Kandia Du Bruyn, Chief Operating Officer</td>
    <td><strong>Meeting:</strong> ${meetDateStr}</td>
    <td><strong>Classification:</strong> Confidential - Board Only</td>
  </tr></table>`;

  // Section 1 — Executive Summary
  const kpiRows = (sections.financialTableRows||[]).slice(0,2);
  const kpi1 = kpiRows[0]||{};
  const kpi2 = kpiRows[1]||{};
  const S1 = `<h2>1. Executive Summary</h2>
  <div class="kpi-row">
    <div class="kpi ${kpi1.resultClass==='neg'?'kpi-n':'kpi-p'}">
      <div class="kpi-label">${kpi1.period||'Current Period'}</div>
      <div class="${kpi1.resultClass==='neg'?'kpi-val-n':'kpi-val-p'}">${kpi1.result||'—'}</div>
      <div class="kpi-sub">${kpi1.keyDriver?kpi1.keyDriver.substring(0,60)+'...':''}</div>
    </div>
    ${kpi2.period?`<div class="kpi ${kpi2.resultClass==='neg'?'kpi-n':'kpi-p'}">
      <div class="kpi-label">${kpi2.period}</div>
      <div class="${kpi2.resultClass==='neg'?'kpi-val-n':'kpi-val-p'}">${kpi2.result}</div>
      <div class="kpi-sub">${(kpi2.keyDriver||'').substring(0,60)+'...'}</div>
    </div>`:''}
  </div>
  <p>${sections.executiveSummary||''}</p>`;

  // Section 2 — Financial Overview
  const finRows = (sections.financialTableRows||[]).map((r,i) =>
    `<tr ${i%2?'class="alt"':''}><td>${r.period||''}</td><td class="${r.resultClass==='neg'?'neg':r.resultClass==='pos'?'pos':''}">${r.result||''}</td><td>${r.keyDriver||''}</td></tr>`
  ).join('');
  const S2 = `<h2>2. Financial Overview</h2>
  <table><thead><tr><th>Period</th><th>Result</th><th>Key Driver</th></tr></thead>
  <tbody>${finRows||'<tr><td colspan="3">No financial data available - check Diane\'s finance emails are in scope.</td></tr>'}</tbody></table>
  ${sections.financeNote?`<p style="font-size:9pt;color:#555">Note: ${sections.financeNote}</p>`:''}
  <div class="coo-box"><strong>COO Assessment</strong><br>${sections.financialAnalysis||''}</div>`;

  // Section 3 — People & Culture
  const pRows = (sections.peopleRows||[]).map((p,i) => {
    const badge = p.status==='at-limit'?'at-limit':p.status==='blocker'?'blocker':p.status==='monitor'?'monitor':'stable';
    return `<tr ${i%2?'class="alt"':''}><td><strong>${p.name||''}</strong></td><td>${p.role||''}</td><td style="text-align:center">${p.capacity||'-'}</td><td style="text-align:center">${p.hours||'No data'}</td><td><span class="badge ${badge}">${(p.status||'stable').charAt(0).toUpperCase()+(p.status||'stable').slice(1).replace('-',' ')}</span></td><td>${p.note||''}</td></tr>`;
  }).join('');
  const S3 = `<h2>3. People and Culture</h2>
  <p>${sections.peopleIntro||''}</p>
  <table><thead><tr><th>Team Member</th><th>Role</th><th>Reported Capacity</th><th>Hrs Logged (Clockify)</th><th>Status</th><th>Key Note</th></tr></thead>
  <tbody>${pRows||'<tr><td colspan="6">No check-in data available.</td></tr>'}</tbody></table>`;

  // Section 4 — Client Delivery
  const clRows = (sections.clientRows||[]).map((r,i) =>
    `<tr ${i%2?'class="alt"':''}><td>${r.client||''}</td><td>${r.status||''}</td></tr>`
  ).join('');
  const nbItems = (sections.newBusiness||[]).map(b=>`<li>${b}</li>`).join('');
  const S4 = `<h2>4. Client Delivery and Operations</h2>
  <p>${sections.clientIntro||''}</p>
  <p style="font-weight:600;margin-bottom:4px">Active and Ongoing Delivery</p>
  <table><thead><tr><th>Client</th><th>Status</th></tr></thead>
  <tbody>${clRows||'<tr><td colspan="2">No active project data.</td></tr>'}</tbody></table>
  ${nbItems?`<p style="font-weight:600;margin:10px 0 4px">New Business Activity</p><ul>${nbItems}</ul>`:''}`

  // Section 5 — Compliance
  const compItems = (sections.complianceItems||[]).map(c=>`<li>${c}</li>`).join('');
  const S5 = `<h2>5. Compliance and Risk</h2>
  <p style="font-weight:600;margin-bottom:6px">Open Compliance Items</p>
  <ul>${compItems||'<li>No open compliance items identified this period.</li>'}</ul>`;

  // Section 6 — Board Items
  const bRows = (sections.boardItems||[]).map((b,i) => {
    const typeCol = b.type==='For Decision'?`color:${RED};font-weight:600`:b.type==='For Awareness'?`color:${AMBER};font-weight:600`:'';
    return `<tr ${i%2?'class="alt"':''}><td>${b.item||''}</td><td style="${typeCol}">${b.type||''}</td><td>${b.action||''}</td></tr>`;
  }).join('');
  const S6 = `<h2>6. Items for Board Decision or Awareness</h2>
  <table><thead><tr><th>Item</th><th>Type</th><th>Recommended Action</th></tr></thead>
  <tbody>${bRows||'<tr><td colspan="3">No items for board this period.</td></tr>'}</tbody></table>`;

  const reportHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head><meta charset="utf-8"><title>COO Board Report - ${monthName} ${yr}</title>${STYLE}</head>
<body><div class="page">${COVER}${S1}${S2}${S3}${S4}${S5}${S6}</div></body></html>`;

  const docHtml = reportHtml; // built server-side above
  const filename = 'board-report-'+yr+'-'+String(mm+1).padStart(2,'0')+'.doc';
  try {
    const cc = await getBlobContainer();
    if (cc) {
      const bc = cc.getBlockBlobClient('board-reports/' + filename);
      await bc.upload(docHtml, Buffer.byteLength(docHtml), {blobHTTPHeaders:{blobContentType:'application/msword'}});
      console.log('[BoardReport] Saved to blob:', filename);
    }
  } catch(e) { console.warn('[BoardReport] Blob save failed:', e.message); }

  // Also save locally
  try { writeFileSync('/home/'+filename, docHtml); } catch(e) {}
  writeFileSync('/home/board-report-latest.json', JSON.stringify({filename, monthName, yr, generatedAt: new Date().toISOString(), meetingSubject}));
  return filename;
}

async function sendBoardReportNotification(meetingSubject, meetingDate, daysUntil, filename) {
  const monthDate = new Date(meetingDate);
  monthDate.setMonth(monthDate.getMonth()-1);
  const monthName = monthDate.toLocaleString('en-AU',{month:'long'});
  const yr = monthDate.getFullYear();

  const emailBody = 'Hi Kandia,\n\nYour COO board report for ' + monthName + ' ' + yr + ' has been prepared and is ready for your review.\n\n' +
    'BOARD MEETING: ' + meetingSubject + '\n' +
    'DATE: ' + meetingDate.toLocaleDateString('en-AU',{weekday:'long',day:'numeric',month:'long',year:'numeric'}) + '\n' +
    'DAYS UNTIL MEETING: ' + daysUntil + '\n\n' +
    'TO DOWNLOAD YOUR REPORT:\n' +
    'Log into Cinderella → COO Duties tab → Board Report section → Download Report\n' +
    'Direct link: https://cinderella-agent-abbacse9gbhcaqeu.australiaeast-01.azurewebsites.net\n\n' +
    'The report has been auto-generated using:\n' +
    '• Staff check-ins and capacity data\n' +
    '• Key emails received during the month\n' +
    '• Client project status from Monday.com\n' +
    '• Open action items from your tracker\n\n' +
    'Please review the report and add any additional context before the board meeting.\n\n' +
    'Cinderella\nExecutive Assistant to Kandia Du Bruyn, COO\nRisk 2 Solution';

  const token = await getValidToken();
  const recipientEmail = await getKandiaEmail();
  const subject = '📋 Board Report Ready — ' + monthName + ' ' + yr + ' (Meeting in ' + daysUntil + ' days)';

  // Create a draft in Outlook (Mail.ReadWrite — confirmed working)
  const draftRes = await fetch('https://graph.microsoft.com/v1.0/me/messages', {
    method:'POST',
    headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
    body:JSON.stringify({
      subject,
      body:{contentType:'Text', content:emailBody},
      toRecipients:[{emailAddress:{address:recipientEmail}}],
      importance:'high'
    })
  });
  const draft = await draftRes.json();
  if (!draft.id) {
    throw new Error('Draft creation failed: ' + JSON.stringify(draft.error||draft).substring(0,200));
  }
  console.log('[BoardReport] ✅ Draft created in Outlook Drafts — id:', draft.id.substring(0,30)+'...');
  console.log('[BoardReport] Recipient:', recipientEmail, '| Subject:', subject);

  // Try to send it directly (requires Mail.Send — may fail, that is OK)
  try {
    const sendRes = await fetch('https://graph.microsoft.com/v1.0/me/messages/'+draft.id+'/send', {
      method:'POST', headers:{Authorization:'Bearer '+token}
    });
    if (sendRes.status === 202) {
      console.log('[BoardReport] ✅ Draft sent successfully from Outlook');
    } else {
      const err = await sendRes.json().catch(()=>({}));
      if ((err.error||{}).code === 'ErrorAccessDenied') {
        console.log('[BoardReport] ℹ Mail.Send not granted — draft saved to Outlook Drafts. Kandia can open and send from there.');
      } else {
        console.warn('[BoardReport] Send attempt returned', sendRes.status, JSON.stringify(err).substring(0,200));
      }
    }
  } catch(e) {
    console.warn('[BoardReport] Send attempt failed (draft still saved):', e.message);
  }
  return draft.id;
}

// Manual trigger endpoint
// Force-send: bypass notifiedMonth and lastCheck guards — for manual Thursday trigger
app.post('/board-report/force-send', requireAuth, async (req, res) => {
  try {
    // Clear the notifiedMonth guard so it can re-send
    const state = loadBoardState();
    const prevMonth = state.notifiedMonth;
    state.notifiedMonth = null;
    state.lastCheck = null;
    saveBoardState(state);
    console.log('[BoardReport] Force-send triggered — cleared notifiedMonth:', prevMonth);

    // Find board meeting in next 14 days
    const now = new Date();
    const to = new Date(now.getTime() + 14*24*60*60*1000).toISOString();
    let meetingDate = null;
    let meetingSubject = 'Board Meeting';
    try {
      const cal = await graphGet(`/me/calendarView?startDateTime=${now.toISOString()}&endDateTime=${to}&$select=subject,start,end&$top=20`);
      const boardMeeting = (cal.value||[]).find(e => {
        if (!e.subject) return false;
        const s = e.subject.toLowerCase();
        return s.includes('board') || s.includes('directors meeting') || s.includes('board pack') || s.includes('board paper');
      });
      if (boardMeeting) {
        meetingDate = new Date(boardMeeting.start.dateTime || boardMeeting.start.date);
        meetingSubject = boardMeeting.subject;
        console.log('[BoardReport] Found meeting:', meetingSubject, 'on', meetingDate.toLocaleDateString());
      } else {
        // No calendar match — use next Tuesday as default
        meetingDate = new Date(now);
        const daysTuesday = (2 - now.getDay() + 7) % 7 || 7;
        meetingDate.setDate(now.getDate() + daysTuesday);
        meetingSubject = 'Board Meeting';
        console.log('[BoardReport] No calendar match — defaulting to next Tuesday:', meetingDate.toLocaleDateString());
      }
    } catch(calErr) {
      meetingDate = new Date(now.getTime() + 5*24*60*60*1000);
      console.warn('[BoardReport] Calendar fetch failed:', calErr.message);
    }

    const daysUntil = Math.round((meetingDate - now) / (24*60*60*1000));
    const reportPath = await generateBoardReport(meetingDate, meetingSubject);
    await sendBoardReportNotification(meetingSubject, meetingDate, daysUntil, reportPath);

    // Save state
    const newState = loadBoardState();
    newState.notifiedMonth = meetingDate.toISOString().substring(0,7);
    newState.lastReportPath = reportPath;
    newState.lastReportMeeting = meetingSubject;
    newState.lastReportDate = now.toISOString();
    newState.lastSentDate = now.toISOString();
    newState.lastMeetingDate = meetingDate.toISOString();
    saveBoardState(newState);

    res.json({ success: true, meeting: meetingSubject, daysUntil, reportPath, emailNote: 'Email sent — check your inbox. If not received within 2 minutes, check Outlook Drafts (re-authenticate at /auth/login if needed to grant Mail.Send permission).' });
  } catch(e) {
    console.error('[BoardReport] Force-send error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Reset state — clears notifiedMonth so Thursday trigger fires again
app.post('/board-report/reset-state', requireAuth, (req, res) => {
  const state = loadBoardState();
  const prev = { notifiedMonth: state.notifiedMonth, lastSentDate: state.lastSentDate };
  state.notifiedMonth = null;
  state.lastSentDate = null;
  state.lastMeetingDate = null;
  saveBoardState(state);
  console.log('[BoardReport] State reset manually. Previous:', JSON.stringify(prev));
  res.json({ success: true, cleared: prev, message: 'State cleared — Thursday scheduler will now run and generate the report' });
});

// Debug: show current board state
app.get('/board-report/debug', requireAuth, (req, res) => {
  const state = loadBoardState();
  const now = new Date();
  const dayOfWeek = now.toLocaleDateString('en-AU',{timeZone:'Australia/Brisbane',weekday:'long'});
  res.json({ state, dayOfWeek, serverTime: now.toISOString(), brisbaneTime: now.toLocaleString('en-AU',{timeZone:'Australia/Brisbane'}) });
});

// Debug emails — shows exactly what emails the board report would capture
app.get('/board-report/debug-emails', requireAuth, async (req, res) => {
  try {
    // Default to current report month (last month)
    const now = new Date();
    const reportDate = new Date(now); reportDate.setMonth(reportDate.getMonth() - 1);
    const mm = reportDate.getMonth();
    const yy = reportDate.getFullYear();
    const monthName = reportDate.toLocaleString('en-AU',{month:'long'});

    const since = new Date(yy, mm, 1).toISOString();
    const nowStr = now.toISOString();

    const emailData = await graphGet(
      `/me/messages?$top=150&$filter=receivedDateTime ge ${since} and receivedDateTime lt ${nowStr}` +
      `&$select=subject,from,bodyPreview,importance,receivedDateTime&$orderby=receivedDateTime desc`
    );
    const emails = emailData.value || [];

    const financeEmails = emails.filter(e => {
      const from = (e.from?.emailAddress?.name||'').toLowerCase();
      const subj = (e.subject||'').toLowerCase();
      // Exclude Cinderella's own board report notification emails
      if (subj.includes('board report ready')) return false;
      // Prioritise emails FROM Diane/Kruger - she sends the monthly P&L
      if (from.includes('diane') || from.includes('kruger')) return true;
      // Tight subject keywords only - avoid noise like 'report' or 'monthly'
      return !!subj.match(/payroll|month.?end|year.?end|p&l|profit.?loss|revenue|budget|reconcil|fy2|fy 2|year to date|ytd|cash flow|forecast/i);
    });

    res.json({
      period: monthName + ' ' + yy,
      since, nowStr,
      totalEmails: emails.length,
      financeEmails: financeEmails.map(e => ({
        from: e.from?.emailAddress?.name,
        subject: e.subject,
        date: e.receivedDateTime,
        preview: e.bodyPreview?.substring(0,200)
      })),
      allSubjects: emails.map(e => ({
        from: e.from?.emailAddress?.name,
        subject: e.subject,
        date: e.receivedDateTime?.substring(0,10)
      }))
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Test email — sends a simple test to Kandia and returns the exact API response
app.get('/board-report/test-email', requireAuth, async (req, res) => {
  try {
    const token = await getValidToken();
    const recipientEmail = await getKandiaEmail();
    const results = {};

    // Test 1: sendMail
    try {
      const r1 = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
        method:'POST',
        headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
        body:JSON.stringify({
          message:{subject:'Cinderella test email',body:{contentType:'Text',content:'Test from Cinderella'},toRecipients:[{emailAddress:{address:recipientEmail}}]},
          saveToSentItems:true
        })
      });
      const body1 = r1.status === 202 ? 'SUCCESS (202)' : await r1.text();
      results.sendMail = { status: r1.status, body: body1.substring(0,300) };
    } catch(e) { results.sendMail = { error: e.message }; }

    // Test 2: Create draft
    try {
      const r2 = await fetch('https://graph.microsoft.com/v1.0/me/messages', {
        method:'POST',
        headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
        body:JSON.stringify({subject:'Cinderella draft test',body:{contentType:'Text',content:'Draft test'},toRecipients:[{emailAddress:{address:recipientEmail}}]})
      });
      const d2 = await r2.json();
      results.createDraft = { status: r2.status, id: d2.id, error: d2.error };

      // Test 3: Send the draft
      if (d2.id) {
        const r3 = await fetch(`https://graph.microsoft.com/v1.0/me/messages/${d2.id}/send`, {
          method:'POST', headers:{Authorization:'Bearer '+token}
        });
        const body3 = r3.status === 202 ? 'SUCCESS (202)' : await r3.text();
        results.sendDraft = { status: r3.status, body: body3.substring(0,300) };
      }
    } catch(e) { results.createDraft = { error: e.message }; }

    res.json({ recipientEmail, tokenExpiry: new Date(tokenStore.expires_at).toLocaleString('en-AU'), results });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/board-report/generate', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const filename = await generateBoardReport(req.body.meetingDate ? new Date(req.body.meetingDate) : new Date(now.getTime() + 14*24*60*60*1000), req.body.meetingSubject || 'Board Meeting');
    res.json({ success: true, filename });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/board-report/latest', requireAuth, (req, res) => {
  try {
    const state = JSON.parse(readFileSync('/home/board-report-latest.json','utf8')||'{}');
    res.json(state);
  } catch(e) { res.json({}); }
});

app.get('/board-report/download', requireAuth, async (req, res) => {
  try {
    const state = JSON.parse(readFileSync('/home/board-report-latest.json','utf8')||'{}');
    if (!state.filename) return res.status(404).json({error:'No report generated yet'});
    const content = readFileSync('/home/'+state.filename,'utf8');
    res.setHeader('Content-Disposition','attachment; filename="'+state.filename+'"');
    res.setHeader('Content-Type','application/msword');
    res.send(content);
  } catch(e) { res.status(404).json({error:e.message}); }
});

// ── AURORA PROXY ROUTES ──

// Summary: all projects + invoice totals + overdue deliverables
app.get('/aurora/summary', requireAuth, async (req, res) => {
  try {
    const { projects } = await callAurora('/api/projects');
    const PHASES = ['Enquiry','Proposal','Active','Review','Close-out'];

    const summary = await Promise.all((projects || []).map(async p => {
      let invoices = [], deliverables = [];
      try { ({ invoices } = await callAurora('/api/projects/' + p.id + '/invoices')); } catch(e) {}
      try { ({ deliverables } = await callAurora('/api/projects/' + p.id + '/deliverables')); } catch(e) {}

      const totalInvoiced  = invoices.reduce((s, i) => s + parseFloat(i.amount||0), 0);
      const totalPaid      = invoices.filter(i => i.paid).reduce((s, i) => s + parseFloat(i.amount||0), 0);
      const totalOutstanding = totalInvoiced - totalPaid;
      const overdueDelivs  = deliverables.filter(d => d.status === 'Overdue' || (d.dueDate && new Date(d.dueDate) < new Date() && d.status !== 'Complete'));
      const inProgressDelivs = deliverables.filter(d => d.status === 'In Progress');
      // Log first deliverable structure for debugging field names
      if (deliverables.length > 0 && !global._auroraDelivLogged) {
        console.log('[Aurora] Deliverable fields:', Object.keys(deliverables[0]).join(', '));
        console.log('[Aurora] Deliverable sample:', JSON.stringify(deliverables[0]).substring(0, 200));
        global._auroraDelivLogged = true;
      }

      return {
        id: p.id,
        client: p.clientName,
        project: p.projectName || p.clientName,
        phase: PHASES[p.phase] || 'Unknown',
        phaseNum: p.phase,
        status: p.status || 'Active',
        consultant: p.consultant,
        dueDate: p.dueDate,
        totalInvoiced,
        totalPaid,
        totalOutstanding,
        unpaidInvoices: invoices.filter(i => !i.paid),
        overdueDeliverables: overdueDelivs,
        inProgressDeliverables: inProgressDelivs,
        deliverableCount: deliverables.length
      };
    }));

    const totalOutstandingAll = summary.reduce((s, p) => s + p.totalOutstanding, 0);
    const totalOverdue        = summary.reduce((s, p) => s + p.overdueDeliverables.length, 0);
    const activeProjects      = summary.filter(p => p.phaseNum >= 1 && p.phaseNum <= 3);

    res.json({ projects: summary, totalOutstandingAll, totalOverdue, activeProjects: activeProjects.length });
  } catch(e) {
    console.error('[Aurora] Summary error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Raw projects list
app.get('/aurora/projects', requireAuth, async (req, res) => {
  try {
    const data = await callAurora('/api/projects');
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Single project detail with invoices + deliverables
app.get('/aurora/projects/:id', requireAuth, async (req, res) => {
  try {
    const [proj, inv, del] = await Promise.all([
      callAurora('/api/projects/' + req.params.id),
      callAurora('/api/projects/' + req.params.id + '/invoices').catch(() => ({ invoices: [] })),
      callAurora('/api/projects/' + req.params.id + '/deliverables').catch(() => ({ deliverables: [] }))
    ]);
    res.json({ project: proj.project || proj, invoices: inv.invoices, deliverables: del.deliverables });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── CLOCKIFY INTEGRATION ──
const CLOCKIFY_API_KEY = process.env.CLOCKIFY_API_KEY || '';
const CLOCKIFY_BASE    = 'https://api.clockify.me/api/v1';
const FULL_WEEK_HOURS  = 37.5; // Standard Australian working week

// Map Clockify display names → check-in names
const CLOCKIFY_STAFF_MAP = [
  { clockify: 'Janita',      checkIn: 'Janita Zhang'     },
  { clockify: 'diane.k',     checkIn: 'Diane Kruger'     },
  { clockify: 'garima.a',    checkIn: 'Garima Arora'     },
  { clockify: 'reinette.k',  checkIn: 'Reinette Kruger'  },
  { clockify: 'dani.s',      checkIn: 'Dani Stevenson'   },
  { clockify: 'ross.m',      checkIn: 'Ross Mackenzie'   },
  { clockify: 'cherry.a',    checkIn: 'Cherry Abadeza'   },
  // Paul Johnston not in Clockify
];

async function callClockify(path) {
  if (!CLOCKIFY_API_KEY) throw new Error('CLOCKIFY_API_KEY not set in environment variables');
  const res = await fetch(CLOCKIFY_BASE + path, {
    headers: { 'X-Api-Key': CLOCKIFY_API_KEY, 'Content-Type': 'application/json' }
  });
  if (!res.ok) {
    const err = await res.text().catch(() => '');
    throw new Error('Clockify ' + res.status + ': ' + err.substring(0, 200));
  }
  return res.json();
}

// Get the current week Mon-Sun in Brisbane time (UTC+10, no DST)
function getBrisbaneWeekRange() {
  const OFFSET_MS = 10 * 60 * 60 * 1000; // UTC+10
  const nowUTC = new Date();
  const brisbaneNow = new Date(nowUTC.getTime() + OFFSET_MS);
  const dow = brisbaneNow.getUTCDay(); // 0=Sun,1=Mon,...,6=Sat
  const daysFromMon = dow === 0 ? 6 : dow - 1;

  // Monday 00:00 Brisbane
  const monday = new Date(brisbaneNow);
  monday.setUTCDate(brisbaneNow.getUTCDate() - daysFromMon);
  monday.setUTCHours(0, 0, 0, 0);

  // Sunday 23:59:59 Brisbane
  const sunday = new Date(monday);
  sunday.setUTCDate(monday.getUTCDate() + 6);
  sunday.setUTCHours(23, 59, 59, 999);

  // Convert Brisbane local → UTC for Clockify API
  return {
    start: new Date(monday.getTime() - OFFSET_MS).toISOString(),
    end:   new Date(sunday.getTime() - OFFSET_MS).toISOString(),
    weekLabel: monday.toLocaleDateString('en-AU', { day: 'numeric', month: 'short', timeZone: 'Australia/Brisbane' })
      + ' – ' + sunday.toLocaleDateString('en-AU', { day: 'numeric', month: 'short', timeZone: 'Australia/Brisbane' })
  };
}

// Parse ISO 8601 duration (PT8H30M15S) → decimal hours
function parseDuration(iso) {
  if (!iso) return 0;
  const match = iso.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  return (parseInt(match[1] || 0)) + (parseInt(match[2] || 0) / 60) + (parseInt(match[3] || 0) / 3600);
}

// Match Clockify user to our staff map
function matchClockifyUser(user) {
  const name = (user.name || '').toLowerCase();
  const email = (user.email || '').toLowerCase();
  return CLOCKIFY_STAFF_MAP.find(m => {
    const c = m.clockify.toLowerCase();
    return name.includes(c) || email.includes(c) || email.startsWith(c);
  });
}

// Generate intelligence flags comparing Clockify hours to check-in capacity
function generateFlags(staffName, actualHours, checkIn) {
  const flags = [];

  if (!checkIn) {
    if (actualHours > 0) {
      flags.push({
        message: actualHours.toFixed(1) + 'h logged in Clockify but no check-in submitted — ask them to complete their weekly check-in',
        severity: 'medium'
      });
    }
    return flags;
  }

  const capacity = checkIn.capacity || 0;
  const impliedHours = (capacity / 100) * FULL_WEEK_HOURS;
  const diff = actualHours - impliedHours;
  const pctVariance = impliedHours > 0 ? Math.abs(diff) / impliedHours : 0;

  if (actualHours === 0 && capacity > 30) {
    flags.push({
      message: 'Reported ' + capacity + '% capacity but zero hours logged in Clockify — time tracking missing or not using Clockify this week',
      severity: 'high'
    });
  } else if (diff > FULL_WEEK_HOURS * 0.25) {
    // Logging significantly more than capacity implies → burnout underreporting
    flags.push({
      message: 'Logged ' + actualHours.toFixed(1) + 'h but check-in says ' + capacity + '% (' + impliedHours.toFixed(1) + 'h implied) — working more than they reported. Burnout risk.',
      severity: 'high'
    });
  } else if (pctVariance > 0.35 && diff < 0 && capacity > 50) {
    // Significantly fewer hours than capacity implies → overreporting capacity
    flags.push({
      message: 'Reported ' + capacity + '% capacity (' + impliedHours.toFixed(1) + 'h implied) but only logged ' + actualHours.toFixed(1) + 'h — overstating capacity or not tracking all time',
      severity: 'medium'
    });
  } else if (pctVariance > 0.2 && diff < 0) {
    flags.push({
      message: actualHours.toFixed(1) + 'h logged vs ' + impliedHours.toFixed(1) + 'h implied (' + capacity + '% capacity) — ' + Math.round(pctVariance * 100) + '% gap. Check time is being tracked fully.',
      severity: 'low'
    });
  }

  return flags;
}

// ── CLOCKIFY STATUS ──
app.get('/clockify/status', requireAuth, async (req, res) => {
  if (!CLOCKIFY_API_KEY) return res.json({ connected: false, reason: 'CLOCKIFY_API_KEY not set' });
  try {
    const workspaces = await callClockify('/workspaces');
    const ws = (workspaces || []).find(w => w.name === 'Risk 2 Solution') || workspaces[0];
    if (!ws) return res.json({ connected: false, reason: 'Workspace "Risk 2 Solution" not found' });
    res.json({ connected: true, workspace: ws.name, workspaceId: ws.id });
  } catch(e) {
    res.json({ connected: false, reason: e.message });
  }
});

// ── CLOCKIFY SUMMARY — cross-reference hours vs check-in capacity ──
app.get('/clockify/summary', requireAuth, async (req, res) => {
  try {
    // 1. Get workspace
    const workspaces = await callClockify('/workspaces');
    const ws = (workspaces || []).find(w => w.name === 'Risk 2 Solution') || workspaces[0];
    if (!ws) throw new Error('Workspace "Risk 2 Solution" not found in your Clockify account');
    const wsId = ws.id;

    // 2. Get all workspace users
    const users = await callClockify('/workspaces/' + wsId + '/users?page-size=50');

    // 3. Get this week's date range (Brisbane time)
    const { start, end, weekLabel } = getBrisbaneWeekRange();

    // 4. Load this week's check-in data for cross-reference
    let checkIns = [];
    try {
      const raw = JSON.parse(readFileSync('/home/checkins.json', 'utf8') || '[]');
      const weekStart = new Date(start);
      const weekEnd   = new Date(end);
      // Get most recent check-in per person this week
      const byName = {};
      raw.forEach(c => {
        if (!c.submitted) return;
        const d = new Date(c.submitted);
        if (d >= weekStart && d <= weekEnd) {
          const key = (c.name || '').toLowerCase();
          if (!byName[key] || new Date(c.submitted) > new Date(byName[key].submitted)) {
            byName[key] = c;
          }
        }
      });
      checkIns = Object.values(byName);
    } catch(e) { console.warn('[Clockify] Could not load check-ins:', e.message); }

    function findCheckIn(staffName) {
      if (!staffName) return null;
      const target = staffName.toLowerCase();
      return checkIns.find(c => {
        const name = (c.name || '').toLowerCase();
        return name === target || name.includes(target.split(' ')[0]) || target.includes(name.split(' ')[0]);
      }) || null;
    }

    // 5. For each matched user, get their time entries for the week
    const summary = [];
    for (const user of users) {
      const match = matchClockifyUser(user);
      if (!match) continue; // Skip unrecognised users

      let totalHours = 0;
      const projectBreakdown = {};

      try {
        const entries = await callClockify(
          '/workspaces/' + wsId + '/user/' + user.id +
          '/time-entries?start=' + encodeURIComponent(start) + '&end=' + encodeURIComponent(end) + '&page-size=500'
        );
        (entries || []).forEach(entry => {
          let hrs = 0;
          if (entry.timeInterval) {
            if (entry.timeInterval.duration) {
              hrs = parseDuration(entry.timeInterval.duration);
            } else if (entry.timeInterval.start && entry.timeInterval.end) {
              hrs = (new Date(entry.timeInterval.end) - new Date(entry.timeInterval.start)) / 3600000;
            }
          }
          totalHours += hrs;
          const proj = entry.projectName || 'No project';
          projectBreakdown[proj] = (projectBreakdown[proj] || 0) + hrs;
        });
      } catch(e) {
        console.warn('[Clockify] Could not get entries for', user.name, ':', e.message);
      }

      totalHours = Math.round(totalHours * 10) / 10;

      // Round project hours
      Object.keys(projectBreakdown).forEach(k => {
        projectBreakdown[k] = Math.round(projectBreakdown[k] * 10) / 10;
      });

      const checkIn = findCheckIn(match.checkIn);
      const capacity = checkIn ? (checkIn.capacity || 0) : null;
      const impliedHours = capacity !== null ? Math.round((capacity / 100) * FULL_WEEK_HOURS * 10) / 10 : null;
      const flags = generateFlags(match.checkIn, totalHours, checkIn);

      summary.push({
        name: match.checkIn,
        clockifyName: user.name,
        totalHours,
        impliedHours,
        capacity,
        variance: impliedHours !== null ? Math.round((totalHours - impliedHours) * 10) / 10 : null,
        projects: projectBreakdown,
        flags,
        checkIn: checkIn ? { capacity, projects: checkIn.projects, blockers: checkIn.blockers } : null
      });
    }

    // Sort: highest flags first, then by variance
    summary.sort((a, b) => b.flags.length - a.flags.length || Math.abs(b.variance||0) - Math.abs(a.variance||0));

    const totalFlags = summary.reduce((n, s) => n + s.flags.length, 0);
    const totalHoursLogged = Math.round(summary.reduce((n, s) => n + s.totalHours, 0) * 10) / 10;

    res.json({ summary, totalFlags, totalHoursLogged, weekLabel, weekStart: start, weekEnd: end });

  } catch(e) {
    console.error('[Clockify] Summary error:', e.message);
    res.status(500).json({ error: e.message });
  }
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
    const staff = [];
    const prompt = `You are Cinderella, elite COO executive assistant for Risk 2 Solution Group. Risk 2 Solution Group is Australia's most awarded integrated risk management company, providing professional services in:
- Risk Management (Presilience® programs, Business Continuity, CRO-as-a-Service, Risk Assessments)
- Security (SoCI compliance, OVA prevention, Security consulting, CSO-as-a-Service)
- Technology & Cybersecurity (Maturity Assessments, vCISO, SOC monitoring, Vulnerability Remediation)
- Training & Education (RTO #4785, Postgrad qualifications, R2S Academy eLearning, bespoke programs)
- Emergency Planning Services (EMPs, Evacuation Diagrams, Warden Training, BCP, CIM)
- Research & Events (ASRC, ISRM, PSG Conference, Presilience® Summits)
ISO Certified: 9001:2015, 45001:2018, 14001:2015, 18788:2015
20+ years | 800+ clients | 150,000+ people trained
Head Office: Murrarie QLD | Operates Australia-wide and internationally
NOTE: Medical division has been fully divested — never reference medical personnel or medical services.
Analyse and return ONLY raw JSON with no markdown.
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
      body: JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 350, messages: [{ role: "user", content: prompt }] })
    });
    if (!res.ok) return;
    const data = await res.json();
    if (data?.content?.[0]?.text) {
      const clean = data.content[0].text.replace(/```json/g,'').replace(/```/g,'').trim();
      try { latestOutput = JSON.parse(clean); } catch(e) {}
    }
    // Check board meeting schedule (Thursdays only)
    await checkBoardMeetingSchedule();
  } catch (err) {
    console.error("❌ Error:", err.message);
  } finally {
    isRunning = false;
  }
}

// Only runs during Brisbane business hours (7am–6pm), every 30 minutes
function isBrisbaneBusinessHours() {
  const hour = parseInt(
    new Date().toLocaleString('en-AU', {
      timeZone: 'Australia/Brisbane',
      hour: 'numeric',
      hour12: false
    })
  );
  return hour >= 7 && hour <= 18;
}

if (isBrisbaneBusinessHours()) {
  think();
}

setInterval(() => {
  if (isBrisbaneBusinessHours()) {
    think();
  } else {
    console.log('💤 Outside business hours — Cinderella is resting');
  }
}, 1800000);

app.get("/status", (req, res) => {
  res.json(Object.keys(latestOutput).length === 0 ? { status: "initialising" } : latestOutput);
});

app.listen(PORT, () => {
  console.log(`🌙 Cinderella running on port ${PORT}`);
});
