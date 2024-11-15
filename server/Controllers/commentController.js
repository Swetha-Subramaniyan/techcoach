const getConnection = require('../Models/database');


const postComment = async (req, res) => {
    const { groupId, groupMemberIds, commentText, decisionId } = req.body;
    const userId = req.user.id;

    console.log('Request Body:', req.body);
    console.log("Decision ID:", req.body.decisionId); 
    let conn;

    try {
        conn = await getConnection();
        await conn.beginTransaction();

        const group = await conn.query('SELECT id FROM techcoach_lite.techcoach_groups WHERE id = ?', [groupId]);
        if (group.length === 0) {
            console.log("Invalid groupId:", groupId);
            return res.status(400).json({ message: 'Invalid group_id, group does not exist' });
        }

        const decision = await conn.query('SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE decision_id = ?', [decisionId]);
        if (decision.length === 0) {
            console.log("Invalid decisionId:", decisionId);
            return res.status(400).json({ message: 'Invalid decision_id, decision does not exist' });
        }

        for (const memberId of groupMemberIds) {
            const member = await conn.query('SELECT user_id FROM techcoach_lite.techcoach_users WHERE user_id = ?', [memberId]);
            if (member.length === 0) {
                console.log("Invalid memberId:", memberId);
                return res.status(400).json({ message: `Invalid member_id: ${memberId}, member does not exist` });
            }

            const sql = `
                INSERT INTO techcoach_lite.techcoach_conversations 
                (groupId, groupMember, comment, decisionId, created_at)
                VALUES (?, ?, ?, ?, NOW());
            `;
            const params = [groupId, memberId, commentText, decisionId];
            await conn.query(sql, params);
        }

        await conn.commit();

        res.status(200).json({ message: 'Comments added successfully!' });

    } catch (error) {
        if (conn) {
            await conn.rollback();
        }
        console.error('Error adding comments:', error);
        res.status(500).json({ message: 'Server error while adding comments', error: error.message });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

// const postComment = async (req, res) => {
//     const { groupId, groupMemberId, commentText, decisionId } = req.body;

//     if (Array.isArray(groupMemberId)) {
//         return res.status(400).json({
//             message: 'groupMemberId must be a single value, not an array.',
//         });
//     }

//     const userId = req.user.id; // Assuming user authentication is in place
//     console.log('Request Body:', req.body);
//     let conn;

//     try {
//         conn = await getConnection();
//         await conn.beginTransaction();

//         // Validate groupId
//         const group = await conn.query(
//             'SELECT id FROM techcoach_lite.techcoach_groups WHERE id = ?',
//             [groupId]
//         );
//         if (group.length === 0) {
//             return res.status(400).json({ message: 'Invalid group_id, group does not exist' });
//         }

//         // Validate decisionId
//         const decision = await conn.query(
//             'SELECT decision_id FROM techcoach_lite.techcoach_decision WHERE decision_id = ?',
//             [decisionId]
//         );
//         if (decision.length === 0) {
//             return res.status(400).json({ message: 'Invalid decision_id, decision does not exist' });
//         }

//         // Validate groupMemberId
//         const member = await conn.query(
//             'SELECT user_id FROM techcoach_lite.techcoach_users WHERE user_id = ?',
//             [groupMemberId]
//         );
//         if (member.length === 0) {
//             return res.status(400).json({
//                 message: `Invalid member_id: ${groupMemberId}, member does not exist`,
//             });
//         }

//         // Insert comment into the database
//         const sql = `
//             INSERT INTO techcoach_lite.techcoach_conversations 
//             (groupId, groupMember, comment, decisionId, created_at)
//             VALUES (?, ?, ?, ?, NOW());
//         `;
//         const params = [groupId, groupMemberId, commentText, decisionId];
//         const result = await conn.query(sql, params);

//         // Commit transaction
//         await conn.commit();

//         // Return success response
//         res.status(201).json({
//             message: 'Comment added successfully!',
//             comment: {
//                 id: result.insertId.toString(),
//                 groupId,
//                 groupMember: groupMemberId,
//                 comment: commentText,
//                 decisionId,
//             },
//         });
//     } catch (error) {
//         if (conn) {
//             await conn.rollback();
//         }
//         console.error('Error adding comment:', error.message);
//         res.status(500).json({
//             message: 'Server error while adding comment',
//             error: error.message,
//         });
//     } finally {
//         if (conn) {
//             conn.release();
//         }
//     }
// };

const getComments = async (req, res) => {
    const { groupId, decisionId } = req.params;
    const userId = req.user.id;
    let conn;

    try {
        const conn = await getConnection();

        const comments = await conn.query(`
        SELECT
                tc.id,
                tc.groupId,
                tc.groupMember,
                tc.decisionId,
                tc.comment,
                tc.created_at,
                tc.parentCommentId,
                tc.updated_at,
                tu.user_id,
                tu.displayname,
                tu.email,
                g.type_of_group
            FROM
                techcoach_lite.techcoach_conversations tc
            LEFT JOIN
                techcoach_lite.techcoach_users tu ON tc.groupMember = tu.user_id
            JOIN 
                techcoach_lite.techcoach_groups g ON tc.groupId = g.id    
            WHERE 
                tc.groupId = ? AND tc.decisionId = ?

      `, [groupId, decisionId]);


      comments.forEach(comment => {
        comment.type_of_member = comment.groupMember === userId ? 'author' : 'member';
    });

        res.status(200).json({comments});

    } catch (error) {
        console.error('Error fetching comments:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ message: 'Server error while fetching comments' });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

const getDecisionComments = async (req, res) => {
    const { decisionId } = req.params;
    const userId = req.user.id;
    let conn;

    try {
        const conn = await getConnection();

        const comments = await conn.query(`
        SELECT
                tc.id,
                tc.groupId,
                tc.groupMember,
                tc.decisionId,
                tc.comment,
                tc.created_at,
                tc.parentCommentId,
                tc.updated_at,
                tu.user_id,
                tu.displayname,
                tu.email,
                g.type_of_group
            FROM
                techcoach_lite.techcoach_conversations tc
            LEFT JOIN
                techcoach_lite.techcoach_users tu ON tc.groupMember = tu.user_id
            JOIN 
                techcoach_lite.techcoach_groups g ON tc.groupId = g.id    
            WHERE 
                tc.decisionId = ? AND g.type_of_group = 'decision_circle'

      `, [decisionId]);


      comments.forEach(comment => {
        comment.type_of_member = comment.groupMember === userId ? 'author' : 'member';
    });

        res.status(200).json({comments});

    } catch (error) {
        console.error('Error fetching comments:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ message: 'Server error while fetching comments' });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

const updateComment = async (req, res) => {
    const commentId = req.params.commentId;
    const { comment } = req.body;
    let conn;

    try {
        const conn = await getConnection();

        const sql = `
        UPDATE techcoach_lite.techcoach_conversations
        SET comment = ?, updated_at = NOW()
        WHERE id = ?
      `;

        const result = await conn.query(sql, [comment, commentId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        res.status(200).json({ message: 'Comment updated successfully!' });
    } catch (error) {
        console.error('Error updating comment:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ message: 'Server error while updating comment' });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

const replyToComment = async (req, res) => {
    const { parentCommentId, groupId, commentText, decisionId } = req.body;
    console.log('parentId',parentCommentId);
    console.log('groupId',groupId);
    console.log('commentText',commentText);
    console.log('decision',decisionId);
    const userId = req.user.id;
    let conn;

    console.log('Request bodyy:',req.body);
    console.log('decision Id:',decisionId);
    try {
        conn = await getConnection();
        await conn.beginTransaction();

        // Check if the parent comment exists
        const parentComment = await conn.query('SELECT id FROM techcoach_lite.techcoach_conversations WHERE id = ?', [parentCommentId]);
        if (parentComment.length === 0) {
            console.log("Invalid parentCommentId:", parentCommentId);
            return res.status(400).json({ message: 'Invalid parent comment ID, comment does not exist' });
        }

        // Check if the group exists
        const group = await conn.query('SELECT id FROM techcoach_lite.techcoach_groups WHERE id = ?', [groupId]);
        if (group.length === 0) {
            console.log("Invalid groupId:", groupId);
            return res.status(400).json({ message: 'Invalid group_id, group does not exist' });
        }

        // Insert the reply comment
        const sql = `
            INSERT INTO techcoach_lite.techcoach_conversations 
            (groupId, groupMember, comment, decisionId, parentCommentId, created_at)
            VALUES (?, ?, ?, ?, ?, NOW());
        `;
        const params = [groupId, userId, commentText, decisionId, parentCommentId];
        await conn.query(sql, params);

        await conn.commit();
        res.status(200).json({ message: 'Reply added successfully!' });
    } catch (error) {
        if (conn) {
            await conn.rollback();
        }
        console.error('Error adding reply comment:', error);
        res.status(500).json({ message: 'Server error while adding reply comment', error: error.message });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

const deleteComment = async (req, res) => {
    const { commentId } = req.params;
    let conn;

    try {
        const conn = await getConnection();

        const result = await conn.query('DELETE FROM techcoach_lite.techcoach_conversations WHERE id = ?', [commentId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        res.status(200).json({ message: 'Comment deleted successfully!' });
    } catch (error) {
        console.error('Error deleting comment:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ message: 'Server error while deleting comment' });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

// group name Controllers
const postdecisionGroup = async (req, res) => {
    const { type_of_group = 'decision_circle', group_name } = req.body;

    let conn;

    try {
        conn = await getConnection();
        await conn.beginTransaction();

        const created_by = req.user.id;

        // Insert into the decision group table
        const groupResult = await conn.query(
            `INSERT INTO techcoach_lite.techcoach_groups (created_by, created_at, type_of_group, group_name) VALUES (?, NOW(), ?, ?)`,
            [created_by, type_of_group, group_name]
        );

        console.log('Group Result:', groupResult);  // Log the result to inspect its structure

        // Use groupResult.insertId if the result is an object
        const groupId = groupResult.insertId ? groupResult.insertId.toString() : groupResult[0].insertId.toString();
        await conn.commit();

        res.status(200).json({ message: 'Decision Group Created successfully', groupId });
    } catch (error) {
        console.error('Error in creating Decision Group:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ error: 'An error occurred while processing your request' });
    } finally {
        if (conn) {
            conn.release();
        }
    }
};

const getAlldecisionGroup = async (req, res) => {
    const {type_of_group ="decision_circle"} = req.query;
    let conn;
    try {
        conn = await getConnection();

        const created_by = req.user.id;

        // Fetch group_name and type_of_group from the decision group table
        const query = 'SELECT id, group_name, type_of_group, created_at FROM techcoach_lite.techcoach_groups WHERE type_of_group = ? AND created_by = ?';
        const rows = await conn.query(query, [type_of_group,created_by]);

        // Check if any rows are returned
        if (rows.length === 0) {
            return res.status(404).json({ message: 'No decision groups found' });
        }

        // Return the results as JSON
        res.status(200).json(rows);
    } catch (error) {
        console.error('Error fetching decision group', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ error: 'An error occurred while fetching decision groups' });
    } finally {
        if (conn) conn.release();
    }
};

const getDecisionGroup = async (req, res) => {
    const { id } = req.params;

    let conn;
    try {
        conn = await getConnection();

        const rows = await conn.query(
            `SELECT id, group_name, type_of_group FROM techcoach_lite.techcoach_groups WHERE id = ?`,
            [id]
        );

        // Check if any rows are returned
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Decision group not found' });
        }

        // Return the results as JSON
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error('Error fetching decision group by ID:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ error: 'An error occurred while fetching the decision group' });
    } finally {
        if (conn) conn.release();
    }
};

const putDecisionGroup = async (req, res) => {
    const { id } = req.params;
    const { group_name } = req.body;

    let conn;

    try {
        conn = await getConnection();
        await conn.beginTransaction();


        const existingGroup = await conn.query(
            `SELECT * FROM techcoach_lite.techcoach_groups WHERE id = ?`,
            [id]
        );

        if (existingGroup.length === 0) {
            return res.status(404).json({ message: 'Decision group not found' });
        }

        // Update the decision group data
        await conn.query(
            `UPDATE techcoach_lite.techcoach_groups SET group_name = ? WHERE id = ?`,
            [group_name, id]
        );

        await conn.commit();

        res.status(200).json({ message: 'Decision group updated successfully' });
    } catch (error) {
        console.error('Error updating decision group:', error);
        await conn.rollback();
        res.status(500).json({ error: 'An error occurred while updating the decision group' });
    } finally {
        if (conn) conn.release();
    }
};

const deleteDecisionGroup = async (req, res) => {
    const { id } = req.params; // Get id from URL parameters

    let conn;
    try {
        conn = await getConnection();

        // Check if the decision group exists before deleting
        const existingRows = await conn.query(
            `SELECT * FROM techcoach_lite.techcoach_groups WHERE id = ?`,
            [id]
        );

        if (existingRows.length === 0) {
            return res.status(404).json({ message: 'Decision group not found' });
        }

        // Delete the decision group
        await conn.query(
            `DELETE FROM techcoach_lite.techcoach_groups WHERE id = ?`,
            [id]
        );

        res.status(200).json({ message: 'Decision group deleted successfully' });
    } catch (error) {
        console.error('Error deleting decision group:', error);
        if (conn) {
            await conn.rollback();
        }
        res.status(500).json({ error: 'An error occurred while deleting the decision group' });
    } finally {
        if (conn) conn.release();
    }
};

module.exports = {
    // Conversation Controllers
    postComment,
    getComments,
    getDecisionComments,
    updateComment,
    replyToComment,
    deleteComment,

    // groupNames controller
    postdecisionGroup,
    getAlldecisionGroup,
    getDecisionGroup,
    putDecisionGroup,
    deleteDecisionGroup,
}