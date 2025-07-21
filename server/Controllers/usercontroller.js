const getConnection = require('../Models/database');
const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc'; // Defin the standard algorithm

/**
 * @param {string} keyString - The user's unique key.
 * @returns {string} A 32-byte key.
 */
const getSecureKey = (keyString) => {
  return crypto.createHash('sha256').update(String(keyString)).digest('base64').substr(0, 32);
};

/**
 * @param {string} text - The text to encrypt.
 * @param {string} userKey - The user's unique key.
 * @returns {string} The IV and encrypted text, separated by a colon.
 */
const encryptText = (text, userKey) => {
  const key = getSecureKey(userKey);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
};

/**
* @param {string} text - The encrypted text.
 * @param {string} userKey - The user's unique key.
 * @returns {string|null} The decrypted text, or null if input is invalid.
 */
const decryptText = (text, userKey) => {
  if (!text || typeof text !== 'string') {
    return null;
  }

  if (text.includes(':')) {
    try {
      // --- NEW DECRYPTION LOGIC ---
      const key = getSecureKey(userKey);
      const textParts = text.split(':');
      const iv = Buffer.from(textParts.shift(), 'hex');
      const encryptedText = Buffer.from(textParts.join(':'), 'hex');
      const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key), iv);
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString();
    } catch (error) {
      console.error("Failed to decrypt new format data:", error);
      return null;
    }
  } else {
    try {
      const decipher = crypto.createDecipher('aes-256-cbc', userKey);
      let decrypted = decipher.update(text, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      console.error("Failed to decrypt old format data:", error);
      return null;
    }
  }
};

const getUserList = async (req, res) => {
    let conn;
    try {
        const userId = req.user.id;
        conn = await getConnection();
        const tasks = await conn.query(`SELECT * FROM techcoach_lite.techcoach_users WHERE user_id = ?;`, [userId]);
        res.status(200).json({ message: 'User List Fetched successfully', tasks });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'An error occurred while processing your request' });
    } finally {
        if (conn) conn.release();
    }
};

const postGeneralProfile = async (req, res) => {
    const { attitude, strength, weakness, opportunity, threat } = req.body;
    let conn;
    try {
        conn = await getConnection();
        await conn.beginTransaction();
        const userId = req.user.id;

        // NOTE: The old 'encryptText' function that was here has been removed.
        // It now uses the secure one defined at the top of the file.

        const headersAndValues = [
            { headerName: 'Attitude', headerValue: attitude },
            { headerName: 'Strength', headerValue: strength },
            { headerName: 'Weakness', headerValue: weakness },
            { headerName: 'Opportunity', headerValue: opportunity },
            { headerName: 'Threat', headerValue: threat }
        ];

        for (const { headerName, headerValue } of headersAndValues) {
            if (headerValue && headerValue.length > 0) {
                const headerRows = await conn.query(`SELECT header_id FROM techcoach_lite.techcoach_profile_swot_headers WHERE header_name = ? AND type_of_profile = 'Profile'`, [headerName]);
                const headerId = headerRows[0]?.header_id;
                if (!headerId) throw new Error(`Header ID not found for header name: ${headerName}`);

                if (Array.isArray(headerValue)) {
                    for (const value of headerValue) {
                        const encryptedValue = encryptText(value, req.user.key); // Uses new helper
                        await conn.query("INSERT INTO techcoach_lite.techcoach_profile_swot_values (user_id, header_id, header_value) VALUES (?, ?, ?)", [userId, headerId, encryptedValue]);
                    }
                } else {
                    const encryptedValue = encryptText(headerValue, req.user.key); // Uses new helper
                    await conn.query("INSERT INTO techcoach_lite.techcoach_profile_swot_values (user_id, header_id, header_value) VALUES (?, ?, ?)", [userId, headerId, encryptedValue]);
                }
            }
        }
        await conn.commit();
        res.status(200).json({ message: 'General profile data inserted successfully' });
    } catch (error) {
        console.error('Error inserting general profile data:', error);
        if (conn) await conn.rollback();
        res.status(500).json({ error: 'An error occurred while processing your request' });
    } finally {
        if (conn) conn.release();
    }
};

const getMasterProfiles = async (req,res) => {
    let conn;
    try {
        conn = await getConnection();
        const rows = await conn.query("SELECT header_id ,header_name FROM techcoach_lite.techcoach_profile_swot_headers WHERE type_of_profile = 'Profile' ");
        if (rows.length > 0) {
            res.status(200).json({profiles : rows })
        } else {
            res.status(404).json({ message: 'No profiles found' });
        }
    } catch (error) {
        console.log('Error fetching master profiles:',error);
        res.status(500).json({ error:'An error occured while fetching master profiles'});
    } finally {
        if (conn) conn.release();
    }
}

// NOTE: The old 'decryptText' function that was here has been removed and replaced
// by the new secure version at the top of the file.

const getProfile = async (req, res) => {
    const userId = req.user.id;
    const userKey = req.user.key;
    let conn;
    try {
        conn = await getConnection();
        const headerValuesResult = await conn.query(
            `SELECT v.id, h.header_name, v.header_value 
             FROM techcoach_lite.techcoach_profile_swot_values v 
             JOIN techcoach_lite.techcoach_profile_swot_headers h ON v.header_id = h.header_id 
             WHERE v.user_id = ? AND h.type_of_profile = 'Profile'`, [userId]
        );
        const profileDetails = headerValuesResult.reduce((acc, { id, header_name, header_value }) => {
            const key = header_name.toLowerCase();
            if (!acc[key]) acc[key] = [];
            const decryptedValue = decryptText(header_value, userKey); // Uses new helper
            acc[key].push({ id, value: decryptedValue });
            return acc;
        }, {});
        const fullProfile = { user_id: userId, ...profileDetails };
        res.status(200).json(fullProfile);
    } catch (error) {
        console.error('Error retrieving profile data:', error);
        res.status(500).json({ error: 'An error occurred while processing your request' });
    } finally {
        if (conn) conn.release();
    }
};

const putProfile = async (req, res) => {
    const { attitude, strength, weakness, opportunity, threat } = req.body;
    const userKey = req.user.key;
    const userId = req.user.id;
    let conn;
    try {
        conn = await getConnection();
        await conn.beginTransaction();

        // NOTE: The old 'encryptText' function that was here has been removed.

        const allValues = [
            ...attitude.map(item => ({ ...item, headerName: 'attitude' })),
            ...strength.map(item => ({ ...item, headerName: 'strength' })),
            ...weakness.map(item => ({ ...item, headerName: 'weakness' })),
            ...opportunity.map(item => ({ ...item, headerName: 'opportunity' })),
            ...threat.map(item => ({ ...item, headerName: 'threat' }))
        ];

        const existingItems = await conn.query("SELECT id FROM techcoach_lite.techcoach_profile_swot_values WHERE user_id = ?", [userId]);
        const itemsToDelete = new Set(existingItems.map(item => item.id));

        for (const item of allValues) {
            const encryptedValue = encryptText(item.value, userKey); // Uses new helper
            if (item.id) {
                // Update existing item
                await conn.query("UPDATE techcoach_lite.techcoach_profile_swot_values SET header_value = ? WHERE id = ?", [encryptedValue, item.id]);
                itemsToDelete.delete(item.id);
            } else if (item.id === null) {
                // Insert new item
                const headerResult = await conn.query("SELECT header_id FROM techcoach_lite.techcoach_profile_swot_headers WHERE LOWER(header_name) = LOWER(?)", [item.headerName]);
                const headerId = headerResult.length > 0 ? headerResult[0].header_id : null;
                await conn.query("INSERT INTO techcoach_lite.techcoach_profile_swot_values (user_id, header_id, header_value) VALUES (?, ?, ?)", [userId, headerId, encryptedValue]);
            }
        }

        if (itemsToDelete.size > 0) {
            await conn.query("DELETE FROM techcoach_lite.techcoach_profile_swot_values WHERE id IN (?)", [[...itemsToDelete]]);
        }

        await conn.commit();
        res.status(200).json({ message: 'General profile data updated successfully' });
    } catch (error) {
        console.error('Error updating general profile data:', error);
        if (conn) await conn.rollback();
        res.status(500).json({ error: 'An error occurred while processing your request' });
    } finally {
        if (conn) conn.release();
    }
};

const deleteProfile = async (req, res) => {
    const userId = req.user.id;
    let conn;
    try {
        conn = await getConnection();
        await conn.beginTransaction();
        await conn.query("DELETE FROM techcoach_lite.techcoach_decision_swot_linked_info WHERE decision_id IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_decision_reason WHERE decision_id IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_decision_tag_linked_info WHERE decision_id IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_shared_decisions WHERE decisionId IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_conversations WHERE decisionId IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_decision_skill_linked_info WHERE decision_id IN (SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE user_id = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_decision WHERE user_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_soft_skill_value WHERE user_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_profile_swot_values WHERE user_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_personal_info WHERE user_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_login_history WHERE user_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_group_members WHERE group_id IN (SELECT id FROM techcoach_lite.techcoach_groups WHERE created_by = ?)", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_group_members WHERE member_id = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_groups WHERE created_by = ?", [userId]);
        await conn.query("DELETE FROM techcoach_lite.techcoach_users WHERE user_id = ?", [userId]);
        await conn.commit();
        res.status(200).json({ message: 'Profile and associated data deleted successfully' });
    } catch (error) {
        console.error('Error deleting profile:', error);
        if (conn) await conn.rollback();
        res.status(500).json({ error: 'An error occurred while deleting the profile' });
    } finally {
        if (conn) conn.release();
    }
};

module.exports = { getUserList, postGeneralProfile, getMasterProfiles, getProfile, putProfile, deleteProfile };