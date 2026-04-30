console.log("Cinderella is starting...");

// Main loop
async function think() {
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

    const data = await res.json();

    console.log("\n==============================");
    console.log("🧠 Cinderella thinking...\n");

    // FULL DEBUG OUTPUT
    console.log("🔍 RAW RESPONSE:");
    console.log(JSON.stringify(data, null, 2));

    // SAFE PARSE
    if (data && data.content && data.content.length > 0) {
      console.log("\n✅ Parsed Output:\n");
      console.log(data.content[0].text);
    } else {
      console.log("\n❌ Unexpected response format");
    }

  } catch (err) {
    console.error("❌ Error:", err.message);
  }
}

// Run every 10 seconds
setInterval(think, 10000);
