import express from "express";
import crypto from "crypto";
import { readFileSync, writeFileSync, existsSync, appendFileSync, mkdirSync, unlinkSync } from 'fs';

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
const SESSION_PATH = '/home/sessions.json';

function loadSessions() {
  try {
    if (existsSync(SESSION_PATH)) {
      const data = JSON.parse(readFileSync(SESSION_PATH, 'utf8'));
      // Filter out expired sessions (older than 7 days)
      const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000);
      const valid = (data.sessions || []).filter(s => s.created > cutoff).map(s => s.token);
      return { set: new Set(valid), full: (data.sessions || []).filter(s => s.created > cutoff) };
    }
  } catch(e) { console.warn('Session load error:', e.message); }
  return { set: new Set(), full: [] };
}

function saveSessions(sessionFull) {
  try { writeFileSync(SESSION_PATH, JSON.stringify({ sessions: sessionFull }, null, 2)); } catch(e) {}
}

const _sessions = loadSessions();
const activeSessions = _sessions.set;
let sessionFull = _sessions.full;
console.log('✅ Loaded', activeSessions.size, 'active sessions from disk');

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
    sessionFull.push({ token, created: Date.now() });
    saveSessions(sessionFull);
    res.setHeader('Set-Cookie', `cin_session=${token}; Path=/; HttpOnly; Max-Age=604800`);
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
  if (req.path === '/login' || req.path === '/logout' || req.path === '/checkin') return next();
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/cin_session=([^;]+)/);
  if (match && activeSessions.has(match[1])) return next();
  // API routes get JSON 401 (not HTML redirect) so the dashboard handles it gracefully
  if (req.path.startsWith('/proxy') || req.path.startsWith('/graph') || req.path.startsWith('/monday') || req.path.startsWith('/auth/status') || req.path.startsWith('/checkins')) {
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
const MONDAY_BOARD_IDS = [2031906973, 2005758439, 2005747804]; // Project/Client Feedback + Client Projects ONLY

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

app.post('/checkins/submit', (req, res) => {
  try {
    const entry = req.body;
    const existing = loadCheckIns();
    const idx = existing.findIndex(e =>
      e.name && e.name.toLowerCase() === (entry.name||'').toLowerCase() &&
      e.weekEnding === entry.weekEnding
    );
    if (idx >= 0) existing[idx] = entry;
    else existing.push(entry);
    saveCheckIns(existing);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── DOCUMENT LIBRARY STORAGE ──
const DOCS_DIR = '/home/documents';
const DOCS_META_PATH = '/home/documents-meta.json';
try { mkdirSync(DOCS_DIR, { recursive: true }); } catch(e) {}

function loadDocsMeta() {
  try {
    if (existsSync(DOCS_META_PATH)) return JSON.parse(readFileSync(DOCS_META_PATH, 'utf8'));
  } catch(e) { console.warn('DocsMeta load error:', e.message); }
  return [];
}
function saveDocsMeta(meta) {
  try { writeFileSync(DOCS_META_PATH, JSON.stringify(meta, null, 2)); } catch(e) {}
}

app.get('/docs', (req, res) => {
  res.json(loadDocsMeta());
});

app.get('/docs/content/:filename', (req, res) => {
  try {
    const filePath = `${DOCS_DIR}/${req.params.filename}`;
    if (!existsSync(filePath)) return res.status(404).send('');
    res.send(readFileSync(filePath, 'utf8'));
  } catch(e) { res.status(500).send(''); }
});

app.post('/docs/upload', (req, res) => {
  try {
    const { name, type, size, content, uploaded } = req.body;
    const safe = name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const unique = Date.now() + '_' + safe;
    writeFileSync(`${DOCS_DIR}/${unique}`, content, 'utf8');
    const meta = loadDocsMeta();
    meta.push({ name, type, size, uploaded, filename: unique });
    saveDocsMeta(meta);
    console.log(`📄 Document saved: ${name} (${Math.round(size/1024)}KB)`);
    res.json({ success: true, filename: unique });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/docs/:filename', (req, res) => {
  try {
    const meta = loadDocsMeta().filter(d => d.filename !== req.params.filename);
    saveDocsMeta(meta);
    try { unlinkSync(`${DOCS_DIR}/${req.params.filename}`); } catch(e) {}
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CLOCKIFY INTEGRATION ──
function parseCfDuration(iso) {
  if (!iso) return 0;
  const m = iso.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!m) return 0;
  return (parseInt(m[1]||0) * 3600 + parseInt(m[2]||0) * 60 + parseInt(m[3]||0)) / 3600;
}

function getWeekBounds() {
  const now = new Date();
  const day = now.getDay();
  const diffToMon = (day === 0) ? -6 : 1 - day;
  const monday = new Date(now);
  monday.setDate(now.getDate() + diffToMon);
  monday.setHours(0, 0, 0, 0);
  return { start: monday.toISOString(), end: now.toISOString() };
}

app.get('/clockify/status', async (req, res) => {
  const apiKey = process.env.CLOCKIFY_API_KEY;
  if (!apiKey) return res.json({ connected: false, error: 'CLOCKIFY_API_KEY not set in environment variables' });
  try {
    const r = await fetch('https://api.clockify.me/api/v1/workspaces', { headers: { 'X-Api-Key': apiKey } });
    if (!r.ok) return res.json({ connected: false, error: 'Invalid API key' });
    const ws = await r.json();
    res.json({ connected: true, workspace: ws[0]?.name || 'Unknown' });
  } catch(e) { res.json({ connected: false, error: e.message }); }
});

app.get('/clockify/summary', async (req, res) => {
  const apiKey = process.env.CLOCKIFY_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'CLOCKIFY_API_KEY not set' });
  try {
    // Get workspace
    const wsRes = await fetch('https://api.clockify.me/api/v1/workspaces', { headers: { 'X-Api-Key': apiKey } });
    const workspaces = await wsRes.json();
    const wsId = workspaces[0]?.id;
    if (!wsId) throw new Error('No Clockify workspace found');

    // Get users and projects in parallel
    const [usersRes, projectsRes] = await Promise.all([
      fetch(`https://api.clockify.me/api/v1/workspaces/${wsId}/users?page-size=50`, { headers: { 'X-Api-Key': apiKey } }),
      fetch(`https://api.clockify.me/api/v1/workspaces/${wsId}/projects?page-size=100&archived=false`, { headers: { 'X-Api-Key': apiKey } })
    ]);
    const users = await usersRes.json();
    const projects = await projectsRes.json();

    // Build project name lookup
    const projectMap = {};
    (Array.isArray(projects) ? projects : []).forEach(p => { projectMap[p.id] = p.name; });

    const { start, end } = getWeekBounds();

    // Fetch time entries for each user
    const summary = [];
    for (const user of (Array.isArray(users) ? users : [])) {
      const entriesRes = await fetch(
        `https://api.clockify.me/api/v1/workspaces/${wsId}/user/${user.id}/time-entries?start=${start}&end=${end}&page-size=200`,
        { headers: { 'X-Api-Key': apiKey } }
      );
      const entries = await entriesRes.json();

      const byProject = {};
      let totalHours = 0;

      for (const entry of (Array.isArray(entries) ? entries : [])) {
        const pName = projectMap[entry.projectId] || 'General';
        const desc = (entry.description || '').trim();
        const hrs = parseCfDuration(entry.timeInterval?.duration);
        totalHours += hrs;
        if (!byProject[pName]) byProject[pName] = { hours: 0, tasks: [] };
        byProject[pName].hours += hrs;
        if (desc && !byProject[pName].tasks.includes(desc)) byProject[pName].tasks.push(desc);
      }

      // Round project hours
      Object.keys(byProject).forEach(k => {
        byProject[k].hours = Math.round(byProject[k].hours * 10) / 10;
      });

      summary.push({
        name: user.name,
        email: (user.email || '').toLowerCase(),
        totalHours: Math.round(totalHours * 10) / 10,
        projects: byProject
      });
    }

    // Cross-reference with check-ins
    const checkIns = loadCheckIns();
    const weekEnd = getWeekBounds().start.split('T')[0];
    // Find most recent check-in for each person
    const recentCI = {};
    checkIns.forEach(ci => {
      const key = (ci.name || '').toLowerCase();
      if (!recentCI[key] || new Date(ci.submitted) > new Date(recentCI[key].submitted)) {
        recentCI[key] = ci;
      }
    });

    // Attach check-in data and flag inconsistencies
    const FULL_WEEK_HOURS = 37.5;
    summary.forEach(person => {
      const firstName = person.name.split(' ')[0].toLowerCase();
      const ciKey = Object.keys(recentCI).find(k => k.includes(firstName) || firstName.includes(k.split(' ')[0]));
      const ci = ciKey ? recentCI[ciKey] : null;

      person.checkIn = ci ? {
        capacity: ci.capacity,
        projects: ci.projects,
        blockers: ci.blockers,
        weekEnding: ci.weekEnding
      } : null;

      // Flag inconsistencies
      person.flags = [];
      if (ci && person.totalHours > 0) {
        const impliedCapacity = Math.round((person.totalHours / FULL_WEEK_HOURS) * 100);
        const reportedCapacity = ci.capacity || 0;
        const gap = Math.abs(impliedCapacity - reportedCapacity);

        if (gap >= 25) {
          person.flags.push({
            type: 'capacity_mismatch',
            severity: gap >= 40 ? 'high' : 'medium',
            message: `Logged ${person.totalHours}h this week (implies ~${impliedCapacity}% capacity) but reported ${reportedCapacity}% in check-in — ${gap}% gap`
          });
        }
        if (person.totalHours < 5 && reportedCapacity > 50) {
          person.flags.push({
            type: 'low_hours',
            severity: 'medium',
            message: `Only ${person.totalHours}h logged this week but reported ${reportedCapacity}% capacity — may not be tracking time`
          });
        }

        // Check project alignment
        const ciProjects = (ci.projects || '').toLowerCase();
        const clockifyProjects = Object.keys(person.projects).map(p => p.toLowerCase());
        if (ciProjects && clockifyProjects.length > 0) {
          const ciProjectList = ciProjects.split(/[,;\/]/).map(p => p.trim()).filter(Boolean);
          const noMatch = ciProjectList.filter(cp =>
            !clockifyProjects.some(cfp => cfp.includes(cp.substring(0,5)) || cp.substring(0,5).includes(cfp.substring(0,3)))
          );
          if (noMatch.length > 0 && noMatch.length >= ciProjectList.length * 0.5) {
            person.flags.push({
              type: 'project_mismatch',
              severity: 'low',
              message: `Check-in mentions "${noMatch.join(', ')}" but no matching Clockify projects found this week`
            });
          }
        }
      } else if (ci && person.totalHours === 0) {
        person.flags.push({
          type: 'no_time_logged',
          severity: 'medium',
          message: `No time logged in Clockify this week but submitted check-in at ${ci.capacity}% capacity`
        });
      }
    });

    res.json({ summary, weekStart: start, workspaceId: wsId });
  } catch(e) {
    console.error('Clockify error:', e.message);
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
      body: JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 350, messages: [{ role: "user", content: prompt }] })
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
