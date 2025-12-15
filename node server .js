const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const APP_ID = 116721;

// ===============================
// HOME TEST
// ===============================
app.get("/", (req, res) => {
  res.send("Nyanyuki Deriv Backend is running ✅");
});

// ===============================
// STEP 1: REDIRECT TO DERIV LOGIN
// ===============================
app.get("/auth/deriv", (req, res) => {
  const redirectUrl = `https://oauth.deriv.com/oauth2/authorize?app_id=${APP_ID}&scope=trading`;
  res.redirect(redirectUrl);
});

// ===============================
// STEP 2: DERIV CALLBACK
// ===============================
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("No authorization code received");
  }

  try {
    const response = await axios.post(
      "https://oauth.deriv.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: APP_ID
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
    );

    const { access_token } = response.data;

    // TEMP: send token to frontend
    res.redirect(`http://localhost:5500/index.html?token=${access_token}`);

  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).send("Deriv authentication failed");
  }
});

// ===============================
const PORT = 5500;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
