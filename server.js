const express = require("express");
const app = express();

app.use(express.json());
app.use(express.static("public"));

app.post("/analyze", (req, res) => {
  const text = req.body.text;
  console.log("Received:", text);
  res.json({ verdict: "Suspicious" });
});

app.listen(3000, () => console.log("Running on http://localhost:3000"));