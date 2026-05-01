import express from "express";
const app = express();
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  next();
});
app.use(express.json()); // ← needed to read request body in /proxy

const PORT = process.env.PORT || 3000;
let latestOutput = {};
let isRunning = false;
console.log("Cinderella is starting...");

// ── PROXY (forwards chat requests from the dashboard to Claude) ──
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

// ── SERVE DASHBOARD (put index.html in a /public folder in your repo) ──
app.use(express.static('public'));

// Main loop
async function think() {
  if (isRunning) return;
  isRunning = true;
  
  const emails = [
    { sender: "Marcus Webb", hoursOld: 26, subject: "Vendor contract approval" },
    { sender: "Karen Liu", hoursOld: 18, subject: "System access approval" }
  ];
  const staff = [
    { name: "John", capacity: 92 },
    { name: "Sarah", capacity: 55 }
  ];
  const prompt = `
You are Cinderella, an elite COO executive assistant.
Analyse the situation below and return ONLY raw JSON.
IMPORTANT RULES:
- Do NOT include markdown, backticks, or explanation
- Return valid JSON only
- Capacity is percentage utilisation:
  - 100% = fully overloaded
  - 0% = fully available
Emails:
${JSON.stringify(emails)}
Staff:
${JSON.stringify(staff)}
Return format:
{
  "priorities": [
    {
      "id": "",
      "task": "",
      "owner": "",
      "urgency": "low | medium | high",
      "reason": ""
    }
  ],
  "risks": [
    {
      "risk": "",
      "impact": "",
      "severity": "low | medium | high"
    }
  ],
  "actions": [
    {
      "action": "",
      "priority": "low | medium | high",
      "owner": "",
      "rationale": ""
    }
  ]
}
`;
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": process.env.ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5",
        max_tokens: 1024,
        messages: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text: prompt
              }
            ]
          }
        ]
      })
    });
    if (!res.ok) {
      console.error("❌ HTTP error:", res.status);
      return;
    }
    const data = await res.json();
    if (!data) {
      console.error("❌ Empty response from API");
      return;
    }
    if (data.type === "error") {
      console.error("❌ Claude API error:", data.error?.message);
      return;
    }
    console.log("\n==============================");
    console.log("🧠 Cinderella thinking...\n");
    console.log("🔍 RAW RESPONSE:");
    console.log(JSON.stringify(data, null, 2));
    if (data && data.content && data.content.length > 0) {
      const clean = data.content[0].text
        .replace(/```json/g, '')
        .replace(/```/g, '')
        .trim();
      try {
        latestOutput = JSON.parse(clean);
        console.log("\n✅ Parsed Output:\n");
        console.log(latestOutput);
      } catch (e) {
        console.log("❌ JSON parse error:");
        console.log(clean);
      }
    } else {
      console.log("\n❌ Unexpected response format");
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
  if (!latestOutput || Object.keys(latestOutput).length === 0) {
    return res.json({ status: "initialising" });
  }
  res.json(latestOutput);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
