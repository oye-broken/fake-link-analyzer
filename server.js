const express = require("express");
const path = require("path");
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Common URL shortener domains (add more anytime)
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
  "rb.gy", "t.ly", "s.id", "bl.ink", "lnkd.in", "wa.me"
]);

// Matches http(s)://..., www....  and bare links like bit.ly/abc
const URL_REGEX = /\b(?:https?:\/\/|www\.)[^\s<>"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\/[^\s<>"']*/gi;

function findLinks(text) {
  const matches = text.match(URL_REGEX) || [];
  return matches.map((raw) => {
    // strip trailing punctuation like . , ) from the end of a link
    const url = raw.replace(/[.,;:!?)\]]+$/, "");
    let host = "";
    try {
      const withProtocol = /^https?:\/\//i.test(url) ? url : "http://" + url;
      host = new URL(withProtocol).hostname.toLowerCase().replace(/^www\./, "");
    } catch (err) {
      host = "";
    }
    return { url, host, shortened: SHORTENERS.has(host) };
  });
}

app.post("/analyze", (req, res) => {
  const text = req.body.text || "";
  console.log("Received:", text);

  const links = findLinks(text);
  const reasons = [];

  links.forEach((link) => {
    if (link.shortened) {
      reasons.push(`${link.url} is a shortened link (${link.host}) - the real destination is hidden`);
    }
  });

  let verdict;
  if (links.length === 0) verdict = "No links found";
  else if (reasons.length > 0) verdict = "Suspicious";
  else verdict = "No shortened links found";

  res.json({ verdict, links, reasons });
});

app.listen(3000, () => console.log("Running on http://localhost:3000"));
