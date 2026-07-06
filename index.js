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
  if (req.path.startsWith('/proxy') || req.path.startsWith('/graph') || req.path.startsWith('/monday') || req.path.startsWith('/auth/status') || req.path.startsWith('/openactions') || req.path.startsWith('/generate') || req.path.startsWith('/docs')) {
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
const SCOPES        = 'offline_access Mail.Read Calendars.ReadWrite Chat.Read ChannelMessage.Read.All';

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
      ? `You are Cinderella, executive assistant to Kandia Robertson (COO) of Risk 2 Solution. Write a complete professional COO board report for ${monthName} ${yr}. Use all data provided. Be specific. No placeholder text. Format with HTML headings and bullet lists. Write every section fully.`
      : `You are Cinderella, executive assistant to Kandia Robertson (COO) of Risk 2 Solution Group. Risk 2 Solution Group is Australia's most awarded integrated risk management company, providing professional services in:
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
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 4000, system: sysPrompt, messages: [{ role: 'user', content: userMsg }] })
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
<p style="font-size:10pt;color:#888">Prepared by Cinderella AI &nbsp;|&nbsp; Kandia Robertson, COO &nbsp;|&nbsp; ${monthName} ${yr}</p>
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
  const state = loadBoardState();
  const now = new Date();
  // Only run once per day max
  if (state.lastCheck && (now - new Date(state.lastCheck)) < 20*60*60*1000) return;
  state.lastCheck = now.toISOString();
  saveBoardState(state);

  const dayOfWeek = now.toLocaleDateString('en-AU',{timeZone:'Australia/Brisbane',weekday:'long'});
  if (dayOfWeek !== 'Thursday') return; // Only act on Thursdays

  console.log('[BoardReport] Thursday detected — scanning calendar for upcoming board meetings...');
  try {
    // Look ahead 14 days for a board meeting
    const from = now.toISOString();
    const to = new Date(now.getTime() + 14*24*60*60*1000).toISOString();
    const cal = await graphGet(`/me/calendarView?startDateTime=${from}&endDateTime=${to}&$select=subject,start,end&$top=20`);
    const boardMeeting = (cal.value||[]).find(e =>
      e.subject && e.subject.toLowerCase().includes('board') &&
      (e.subject.toLowerCase().includes('meeting') || e.subject.toLowerCase().includes('report') || e.subject.toLowerCase().includes('director'))
    );
    if (!boardMeeting) { console.log('[BoardReport] No board meeting found in next 14 days'); return; }

    const meetingDate = new Date(boardMeeting.start.dateTime || boardMeeting.start.date);
    const daysUntil = Math.round((meetingDate - now) / (24*60*60*1000));
    const monthKey = meetingDate.toISOString().substring(0,7);
    console.log('[BoardReport] Board meeting found:', boardMeeting.subject, '— in', daysUntil, 'days (', monthKey, ')');

    // Don't send if we already notified for this month's meeting
    if (state.notifiedMonth === monthKey) { console.log('[BoardReport] Already notified for', monthKey); return; }
    if (daysUntil > 10) { console.log('[BoardReport] Meeting too far out, will check closer to date'); return; }

    // Generate the report
    console.log('[BoardReport] Generating report for', boardMeeting.subject, '...');
    const reportPath = await generateBoardReport(meetingDate, boardMeeting.subject);

    // Send email notification to Kandia
    await sendBoardReportNotification(boardMeeting.subject, meetingDate, daysUntil, reportPath);
    state.notifiedMonth = monthKey;
    state.lastReportPath = reportPath;
    state.lastReportMeeting = boardMeeting.subject;
    state.lastReportDate = now.toISOString();
    saveBoardState(state);
    console.log('[BoardReport] ✅ Notification sent and state saved');
  } catch(e) {
    console.error('[BoardReport] Error:', e.message);
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

  // 1. Staff check-ins for the month
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

  // 2. Emails from the report month (especially Diane's finance updates)
  try {
    const since = new Date(yy, mm, 1).toISOString();
    const until = new Date(yy, mm+1, 1).toISOString();
    const emailData = await graphGet(`/me/messages?$top=50&$filter=receivedDateTime ge ${since} and receivedDateTime lt ${until}&$select=subject,from,body,importance,receivedDateTime&$orderby=receivedDateTime desc`);
    const emails = emailData.value || [];
    // Finance emails (from Diane or about finance/payroll/month end)
    const financeEmails = emails.filter(e => {
      const from = (e.from?.emailAddress?.name||'').toLowerCase();
      const subj = (e.subject||'').toLowerCase();
      return from.includes('diane') || subj.match(/payroll|month.?end|year.?end|finance|financial|invoice|budget|reconcil|p&l|profit|revenue/);
    });
    if (financeEmails.length > 0) {
      context += 'FINANCE & OPERATIONS EMAILS ('+monthName+'):\n';
      financeEmails.slice(0,10).forEach(e => {
        const preview = (e.body?.content||'').replace(/<[^>]*>/g,'').replace(/\s+/g,' ').substring(0,200);
        context += '- From '+( e.from?.emailAddress?.name||'?')+': '+e.subject+'\n  '+preview+'\n';
      });
      context += '\n';
    }
    // Other key emails
    const otherEmails = emails.filter(e => !financeEmails.includes(e)).slice(0,20);
    if (otherEmails.length > 0) {
      context += 'OTHER KEY EMAILS ('+monthName+'):\n';
      otherEmails.forEach(e => {
        context += '- '+(e.from?.emailAddress?.name||'?')+': '+e.subject+(e.importance==='high'?' [HIGH PRIORITY]':'')+'\n';
      });
      context += '\n';
    }
  } catch(e) { console.warn('[BoardReport] Email fetch:', e.message); }

  // 3. Document library - templates and past reports
  try {
    const cc = await getBlobContainer();
    if (cc) {
      const docs = []; const pastReports = [];
      for await (const b of cc.listBlobsFlat()) {
        if (b.name.toLowerCase().match(/board.?report|board.?pack/)) pastReports.push(b.name);
        else docs.push(b.name);
      }
      if (pastReports.length > 0) context += 'PAST BOARD REPORTS IN LIBRARY: '+pastReports.join(', ')+'\n\n';
      if (docs.length > 0) context += 'OTHER DOCUMENTS: '+docs.join(', ')+'\n\n';
    }
  } catch(e) {}

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

  // Generate comprehensive report with AI
  const systemPrompt = `You are Cinderella, elite executive assistant and intelligence analyst for Kandia Robertson (COO) at Risk 2 Solution Group, Australia's most awarded integrated risk management company (Risk Management, Security, Cybersecurity, Training & Education RTO #4785, Emergency Planning). Presilience® is their flagship methodology. Medical division divested — exclude. Nationwide operations, 20+ years, ISO certified.

Generate a comprehensive, professional COO board report for ${monthName} ${yr} for the board meeting: "${meetingSubject}".

Apply best-practice knowledge for:
- Small business COO board reporting standards
- Australian business compliance and regulatory context
- Professional services and consulting firm operations metrics
- Professional services delivery benchmarks
- People & culture best practice for small teams

The report must be:
- Comprehensive but concise (board members are busy — be specific, not verbose)
- Data-driven where evidence exists, clearly flagging gaps where data is limited
- Forward-looking — identify risks, opportunities and recommendations
- Formatted in professional HTML with clear sections and tables where useful

Identify and highlight:
- Gaps in compliance, processes or operations
- Staff welfare concerns from check-in patterns
- Financial trends or anomalies
- Client delivery risks
- Recommendations based on industry best practice`;

  const userMsg = `Generate the full COO board report for ${monthName} ${yr}.

Board meeting: ${meetingSubject}
Meeting date: ${meetingDate.toLocaleDateString('en-AU',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}
Report prepared by: Cinderella AI on behalf of Kandia Robertson, COO

Structure the report with these sections:
1. Executive Summary & Key Highlights
2. People & Culture — staff capacity, wellbeing, skills utilisation, attendance
3. Financial Overview — based on available email data, flag gaps where full P&L not available
4. Client Delivery & Projects — status, risks, upcoming milestones
5. Operations & Platform — technology, systems, process updates
6. Compliance & Risk — regulatory, insurance, certification status and gaps identified
7. Policies & Processes — updates, gaps, improvements implemented or needed
8. Strategic Priorities & Recommendations — COO recommendations for next month
9. Items for Board Decision or Awareness

DATA AVAILABLE:
${context}

Where data is limited, clearly state "Data not available — recommend [specific action]" and apply best-practice benchmarks for a business of this size and type.`;

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method:'POST',
    headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
    body:JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:6000, system:systemPrompt, messages:[{role:'user',content:userMsg}] })
  });
  const aiData = await aiRes.json();
  const reportContent = aiData.content?.[0]?.text || 'Report generation failed — please generate manually.';

  // Build Word-compatible HTML
  const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head><meta charset="utf-8"><title>COO Board Report — ${monthName} ${yr}</title>
<style>
body{font-family:Arial,sans-serif;font-size:11pt;margin:2cm 2.5cm;line-height:1.5;color:#111}
h1{font-size:20pt;color:#1F4E79;border-bottom:2pt solid #1F4E79;padding-bottom:6pt;margin-top:0}
h2{font-size:14pt;color:#2E75B6;margin-top:20pt;margin-bottom:6pt;border-left:4pt solid #2E75B6;padding-left:8pt}
h3{font-size:12pt;color:#2E75B6;margin-top:12pt}
.cover{text-align:center;margin-bottom:40pt;padding:24pt;border:1pt solid #2E75B6;background:#F5F9FF}
table{border-collapse:collapse;width:100%;margin:8pt 0}
td,th{border:.5pt solid #CCC;padding:5pt 8pt;font-size:10pt}
th{background:#EEF3F9;font-weight:bold;text-align:left}
ul,ol{margin:4pt 0;padding-left:20pt}li{margin-bottom:3pt}
.highlight{background:#FFF9E6;border-left:3pt solid #F6C90E;padding:6pt 10pt;margin:8pt 0}
.risk{background:#FFF5F5;border-left:3pt solid #FC8181;padding:6pt 10pt;margin:8pt 0}
.good{background:#F0FFF4;border-left:3pt solid #68D391;padding:6pt 10pt;margin:8pt 0}
</style></head>
<body>
<div class="cover">
<h1>COO Board Report</h1>
<p style="font-size:15pt;color:#2E75B6;margin:6pt 0">Risk 2 Solution</p>
<p style="font-size:12pt;color:#555">${monthName} ${yr}</p>
<p style="font-size:10pt;color:#888;margin-top:8pt">Prepared by Cinderella AI on behalf of Kandia Robertson, COO<br>
For: ${meetingSubject}<br>
Meeting date: ${meetingDate.toLocaleDateString('en-AU',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}</p>
</div>
${reportContent}
</body></html>`;

  // Save to blob storage
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
    'Log into Cinderella → COO Duties tab → Board Report section\n' +
    'Direct link: https://cinderella-agent-abbacse9gbhcaqeu.australiaeast-01.azurewebsites.net\n\n' +
    'The report has been auto-generated using:\n' +
    '• Staff check-ins and capacity data for ' + monthName + '\n' +
    '• Key emails received and sent during the month\n' +
    '• Client project status from Monday.com\n' +
    '• Open action items from your tracker\n' +
    '• Document library and past board reports\n\n' +
    'Please review and add any additional context before the board meeting. The report is a starting point — your judgment and any verbal updates will be essential.\n\n' +
    'Cinderella\nExecutive Assistant to Kandia Robertson, COO\nRisk 2 Solution';

  try {
    const token = await getValidToken();
    const recipientEmail = await getKandiaEmail();
  await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
      method:'POST',
      headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
      body:JSON.stringify({
        message:{
          subject:'📋 Board Report Ready — '+monthName+' '+yr+' (Meeting in '+daysUntil+' days)',
          body:{contentType:'Text', content:emailBody},
          toRecipients:[{emailAddress:{address:recipientEmail}}],
          importance:'high'
        },
        saveToSentItems:true
      })
    });
    console.log('[BoardReport] Notification email sent to', KANDIA_EMAIL);
  } catch(e) {
    console.error('[BoardReport] Email send failed:', e.message);
  }
}

// Manual trigger endpoint
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
