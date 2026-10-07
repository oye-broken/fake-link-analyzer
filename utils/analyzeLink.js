const SUSPICIOUS_WORDS = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'otp', 'kyc', 'prize', 'free', 'gift', 'claim', 'refund'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy', 'is.gd'];
const RISKY_TLDS = ['.xyz', '.top', '.click', '.live', '.icu', '.tk', '.work', '.buzz'];

function analyzeLink(rawUrl) {
  const reasons = [];
  let score = 0;

  let url;
  try {
    url = new URL(rawUrl.startsWith('http') ? rawUrl : 'http://' + rawUrl);
  } catch {
    return { url: rawUrl, score: 0, verdict: 'unknown', reasons: ['Could not read this link'] };
  }

  const host = url.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();

  if (SHORTENERS.includes(host)) { score += 30; reasons.push('Shortened link hides the real destination'); }
  if (url.protocol === 'http:') { score += 15; reasons.push('Not using HTTPS'); }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 40; reasons.push('Uses an IP address instead of a website name'); }
  if (rawUrl.includes('@')) { score += 30; reasons.push('Contains @ which can hide the real site'); }
  if (host.startsWith('xn--') || host.includes('.xn--')) { score += 30; reasons.push('Look-alike (punycode) characters in the domain'); }
  if (RISKY_TLDS.some(t => host.endsWith(t))) { score += 20; reasons.push('Domain ending is often used in scams'); }
  if (host.split('.').length > 4) { score += 15; reasons.push('Too many subdomains'); }
  if (host.includes('-') && host.split('-').length > 2) { score += 10; reasons.push('Many hyphens in the domain'); }

  const hits = SUSPICIOUS_WORDS.filter(w => full.includes(w));
  if (hits.length) { score += Math.min(hits.length * 10, 30); reasons.push('Suspicious words: ' + hits.join(', ')); }

  score = Math.min(score, 100);
  const verdict = score >= 60 ? 'dangerous' : score >= 30 ? 'suspicious' : 'looks safe';
  return { url: rawUrl, score, verdict, reasons };
}

module.exports = analyzeLink;