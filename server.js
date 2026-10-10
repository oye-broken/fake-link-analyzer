const express = require("express");
const path = require("path");
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---------- Lists (add more anytime) ----------

// Common URL shortener domains
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
  "rb.gy", "t.ly", "s.id", "bl.ink", "lnkd.in", "wa.me"
]);

// Brands scammers imitate: name -> their real domains
const BRANDS = {
  paypal: ["paypal.com"],
  amazon: ["amazon.com", "amazon.in"],
  google: ["google.com", "google.co.in"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com", "wa.me"],
  netflix: ["netflix.com"],
  flipkart: ["flipkart.com"],
  paytm: ["paytm.com"],
  phonepe: ["phonepe.com"],
  microsoft: ["microsoft.com"],
  apple: ["apple.com"],
  hdfcbank: ["hdfcbank.com"],
  icicibank: ["icicibank.com"],
  sbi: ["sbi.co.in", "onlinesbi.sbi"],
  irctc: ["irctc.co.in"],
  swiggy: ["swiggy.com"],
  ngit: ["ngit.ac.in"]
};

// Cheap endings that scammers use a lot
const RISKY_TLDS = new Set([
  "xyz", "top", "click", "buzz", "icu", "club", "work", "live",
  "loan", "tk", "ml", "ga", "cf", "gq", "rest", "cyou", "sbs"
]);

// Words that show up in scam links
const RISKY_WORDS = [
  "login", "verify", "update", "secure", "account", "kyc",
  "otp", "bonus", "prize", "reward", "refund", "claim", "free",
  "congratulations", "lottery"
];

// ---------- Finding links ----------

// Matches http(s)://..., www...., links like bit.ly/abc, and bare domains like paypa1.com
// (bare domains only match known endings, so "server.js" is not mistaken for a link)
const URL_REGEX = new RegExp(
  "\\b(?:https?:\\/\\/|www\\.)[^\\s<>\"']+" +
  "|\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.[a-z]{2,}\\/[^\\s<>\"']*" +
  "|\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:com|net|org|in|co|info|io|me|app|site|online|shop|ly|" +
  [...RISKY_TLDS].join("|") + ")\\b",
  "gi"
);

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
    return { url, host };
  });
}

// ---------- Checking a link ----------

function isOfficial(host, domains) {
  return domains.some((d) => host === d || host.endsWith("." + d));
}

// Turn look-alike digits back into letters: paypa1 -> paypal, g00gle -> google
function lookalikeVariants(host) {
  const base = host.replace(/0/g, "o").replace(/3/g, "e").replace(/5/g, "s");
  return [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
}

// Returns { score, reasons } for one link
function checkLink(link) {
  const { url, host } = link;
  const reasons = [];
  let score = 0;
  if (!host) return { score, reasons };

  // 1. Shortened link
  if (SHORTENERS.has(host)) {
    score += 2;
    reasons.push(`${url} is a shortened link (${host}) - the real destination is hidden`);
  }

  // 2. Raw IP address instead of a domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 3;
    reasons.push(`${url} uses a number address (${host}) instead of a real website name`);
  }

  // 3. Pretending to be a known brand
  const variants = lookalikeVariants(host);
  for (const [brand, domains] of Object.entries(BRANDS)) {
    // short names (like "sbi") must be a whole word in the link, longer ones can appear anywhere
    const mentionsBrand = variants.some((v) =>
      brand.length <= 4 ? v.split(/[.-]/).includes(brand) : v.includes(brand)
    );
    if (mentionsBrand && !isOfficial(host, domains)) {
      score += 3;
      reasons.push(`${url} looks like ${brand} but is not an official ${brand} website (${domains[0]})`);
      break;
    }
  }

  // 4. Cheap, often-abused ending like .xyz or .top
  const tld = host.split(".").pop();
  if (RISKY_TLDS.has(tld)) {
    score += 1;
    reasons.push(`${url} ends with .${tld}, which scammers use a lot`);
  }

  // 5. Scammy words in the link (skipped for a brand's real website)
  const lower = url.toLowerCase();
  const found = RISKY_WORDS.filter((w) => lower.includes(w));
  const onRealSite = Object.values(BRANDS).some((domains) => isOfficial(host, domains));
  if (found.length > 0 && !onRealSite) {
    score += 1;
    reasons.push(`${url} contains words often used in scams: ${found.join(", ")}`);
  }

  // 6. Not using HTTPS (https alone proves nothing, so no bonus for it)
  if (/^http:\/\//i.test(url)) {
    score += 1;
    reasons.push(`${url} does not use a secure (https) connection`);
  }

  // 7. "@" in the link can hide the real website
  if (url.includes("@")) {
    score += 2;
    reasons.push(`${url} contains "@" which can hide the real website`);
  }

  // 8. Look-alike (punycode) characters in the domain
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 3;
    reasons.push(`${url} uses look-alike characters in the website name`);
  }

  // 9. Too many parts in the domain
  if (host.split(".").length > 4) {
    score += 1;
    reasons.push(`${url} has too many sub-parts in the website name`);
  }

  return { score, reasons };
}

// ---------- API ----------

app.post("/analyze", (req, res) => {
  const text = req.body.text || "";
  console.log("Received:", text);

  const links = findLinks(text);
  const reasons = [];
  let score = 0;

  links.forEach((link) => {
    const result = checkLink(link);
    score += result.score;
    reasons.push(...result.reasons);
  });

  let verdict;
  if (links.length === 0) verdict = "No links found";
  else if (score >= 3) verdict = "Likely scam";
  else if (score >= 1) verdict = "Suspicious";
  else verdict = "No warning signs found";

  res.json({ verdict, score, links, reasons });
});

app.listen(3000, () => console.log("Running on http://localhost:3000"));