// migrate-swot-stage.js
const crypto = require("crypto");
const getConnection = require("./Models/database");

const ALGORITHM = "aes-256-cbc";

const getSecureKey = (keyString) =>
  crypto.createHash("sha256").update(String(keyString)).digest("base64").substr(0, 32);

const encryptText = (text, userKey) => {
  const key = getSecureKey(userKey);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv);
  let encrypted = cipher.update(text, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
};

const decryptOld = (encryptedHex, userKey) => {
  try {
    const decipher = crypto.createDecipher(ALGORITHM, userKey);
    let decrypted = decipher.update(encryptedHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    return null;
  }
};

const deriveUserKey = (user) =>
  ((user.displayName || "").trim() + (user.email || "").trim());

async function stage() {
  const conn = await getConnection();
  try {
    // Only OLD-format rows (no colon)
    const rows = await conn.query(`
      SELECT
        v.id,
        v.user_id,
        v.header_value,
        u.displayName,
        u.email
      FROM techcoach_lite.techcoach_profile_swot_values v
      JOIN techcoach_lite.techcoach_users u ON v.user_id = u.user_id
      WHERE v.header_value IS NOT NULL
        AND v.header_value <> ''
        AND v.header_value NOT LIKE '%:%'
    `);

    console.log(`OLD-format rows to process: ${rows.length}`);

    let ok = 0, fail = 0, skip = 0;

    for (const row of rows) {
      const userKey = deriveUserKey(row);

      const plain = decryptOld(row.header_value, userKey);
      if (plain === null) {
        console.warn(`❌ row ${row.id}: OLD decrypt failed ${userKey}`);
        fail++;
        continue;
      }

      const newEnc = encryptText(plain, userKey);

      await conn.query(
        `UPDATE techcoach_lite.techcoach_profile_swot_values
           SET header_value_new_1     = ?,
               header_value_new_enc_1 = ?
         WHERE id = ?`,
        [plain, newEnc, row.id]
      );
      ok++;
    }

    console.log(`✅ staged ok=${ok} fail=${fail} skip=${skip}`);
  } catch (err) {
    console.error("Staging error:", err);
  } finally {
    conn.release();
  }
}

stage();