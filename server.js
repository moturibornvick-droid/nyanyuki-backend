// server.js - Nyanyuki.site backend
const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const APP_ID = 116721; // Deriv App ID

// =====================
// Root test route
// =====================
app.get("/", (req, res) => {
  res.send("Nyanyuki Deriv Backend is running ✅");
});

// =====================
// Redirect to Deriv OAuth
// =====================
app.get("/auth/deriv", (req, res) => {
  const redirectUri = "https://nyanyukisite.netlify.app/index.html";
  const url = `https://oauth.deriv.com/oauth2/authorize?app_id=${APP_ID}&scope=trading&redirect_uri=${redirectUri}`;
  res.redirect(url);
});

// =====================
// OAuth callback (Deriv sends code)
// =====================
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("No authorization code");

  try {
    const response = await axios.post(
      "https://oauth.deriv.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: APP_ID,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const accessToken = response.data.access_token;
    // redirect back to frontend
    res.redirect(`https://nyanyukisite.netlify.app/index.html?token=${accessToken}`);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send("OAuth failed");
  }
});

// =====================
// Get account balance
// =====================
app.get("/balance", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send({ error: "No token provided" });

  try {
    const response = await axios.post("https://api.deriv.com/api/v1", {
      authorize: token,
      balance: 1
    });

    const balance = response.data.balance || 0;
    res.json({ balance });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send({ error: "Failed to fetch balance" });
  }
});

// =====================
// Place a trade
// =====================
app.post("/trade", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { botName, stake } = req.body;

  if (!token) return res.status(401).send({ error: "No token provided" });
  if (!botName || !stake) return res.status(400).send({ error: "Missing trade parameters" });

  try {
    const response = await axios.post("https://api.deriv.com/api/v1", {
      authorize: token,
      buy: 1,
      contract_type: "CALL", // example contract
      amount: stake,
      duration: 5,
      duration_unit: "t",
      symbol: "R_50" // Volatility 50 index
    });

    res.json({ result: response.data });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send({ error: "Trade failed" });
  }
});

// =====================
// Start server
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
