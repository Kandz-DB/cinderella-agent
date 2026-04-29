const API_KEY = process.env.ANTHROPIC_KEY;

console.log("Cinderella is starting...");

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

Analyse the situation below and return ONLY JSON.

Emails:
${JSON.stringify(emails)}

Staff:
${JSON.stringify(staff)}

Return:
{
  "priorities": [],
  "risks": [],
  "actions": []
}
`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": API_KEY,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-3-sonnet",
        max_tokens: 500,
        messages: [{ role: "user", content: prompt }]
      })
    });

    const data = await res.json();

    console.log("\n==============================");
    console.log("🧠 Cinderella thinking...\n");
    console.log(data.content[0].text);

  } catch (err) {
    console.error("❌ Error:", err.message);
  }
}

setInterval(think, 10000);
