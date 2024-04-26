
// // // Route to handle POST requests to insert data
// // app.post('/insert_data', async (req, res) => {
// //     const { googleId, displayName, email, image } = req.body;
// //     console.log(email)

// //     try {
// //         const conn = await getConnection();
// //         // Execute the SQL query to insert data
// //         const result = await conn.query("INSERT INTO  taskk.task1 (googleId, displayName, email,image) VALUES (?, ?, ?,?)",
// //             [googleId, displayName, email, image]);

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Send response indicating success
// //         res.status(200).json({ message: 'Data inserted successfully' });
// //     } catch (error) {
// //         console.error('Error inserting data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });

// // app.get('/insert_data', async (req, res) => {
// //     try {
// //         const conn = await getConnection();
// //         // Execute the SQL query to fetch data
// //         const result = await conn.query("SELECT * FROM taskk.task1");

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Send response with the fetched data
// //         res.status(200).json({ data: result });
// //     } catch (error) {
// //         console.error('Error fetching data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });

// // app.put('/profile/:id', async (req, res) => {
// //     try {
// //       const id = req.params.id;
// //       const { image, password, email } = req.body;

// //       // Perform the update operation in your database
// //       // Example: Assuming you have a 'users' collection/table in your database
// //       // Update the user with the given ID
// //       await User.findByIdAndUpdate(id, { image, password, email });

// //       res.status(200).json({ message: 'Profile updated successfully' });
// //     } catch (error) {
// //       console.error('Error updating profile:', error);
// //       res.status(500).json({ error: 'Internal Server Error' });
// //     }
// //   });

// // app.post('/profile', async (req, res) => {
// //     const { YearBorn, Gender, AddedDate, Type, Strength1, Strength2, Skill, Attitude, Weakness, Communication, Opportunity, Threat } = req.body;

// //     try {
// //         const conn = await getConnection();
// //         // Execute the SQL query to insert data
// //         const result = await conn.query("INSERT INTO  taskk.person (YearBorn, Gender, AddedDate, Type, Strength1, Strength2, Skill, Attitude, Weakness, Communication, Opportunity, Threat) VALUES (?, ?, ?,?,?,?,?,?,?,?,?,?)",
// //             [YearBorn, Gender, AddedDate, Type, Strength1, Strength2, Skill, Attitude, Weakness, Communication, Opportunity, Threat]);

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Send response indicating success
// //         res.status(200).json({ message: 'Data inserted successfully' });
// //     } catch (error) {
// //         console.error('Error inserting data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });

// // app.get('/profile', async (req, res) => {
// //     try {
// //         const conn = await getConnection();
// //         // Execute the SQL query to retrieve data
// //         const result = await conn.query("SELECT * FROM taskk.person");

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Send the retrieved data in the response
// //         res.status(200).json({ data: result });
// //     } catch (error) {
// //         console.error('Error retrieving data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });

// // app.get('/profile/:id', async (req, res) => {
// //     const id = req.params.id; // Retrieve the ID parameter from the request URL
// //     try {
// //         const conn = await getConnection();
// //         // Execute the SQL query to retrieve data for the specific ID
// //         const result = await conn.query("SELECT * FROM taskk.person WHERE id = ?", [id]);

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Check if data for the ID was found
// //         if (result.length === 0) {
// //             return res.status(404).json({ error: 'Data not found' });
// //         }

// //         // Send the retrieved data in the response
// //         res.status(200).json({ data: result[0] }); // Assuming only one record is expected
// //     } catch (error) {
// //         console.error('Error retrieving data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });


// // app.put('/profile/:id', async (req, res) => {
// //     const id = req.params.id; // Retrieve the ID parameter from the request URL
// //     const { YearBorn, Gender, AddedDate, Type, Strength1, Strength2, Skill, Attitude, Weakness, Communication, Opportunity, Threat } = req.body;

// //     try {
// //         const conn = await getConn();
// //         // Execute the SQL query to update data
// //         const result = await conn.query("UPDATE taskk.person SET YearBorn=?, Gender=?, AddedDate=?, Type=?, Strength1=?, Strength2=?, Skill=?, Attitude=?, Weakness=?, Communication=?, Opportunity=?, Threat=? WHERE id=?",
// //             [YearBorn, Gender, AddedDate, Type, Strength1, Strength2, Skill, Attitude, Weakness, Communication, Opportunity, Threat, id]);

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Check if any rows were affected by the update
// //         if (result.affectedRows === 0) {
// //             return res.status(404).json({ error: 'Data not found or no changes made' });
// //         }

// //         // Send response indicating success
// //         res.status(200).json({ message: 'Data updated successfully' });
// //     } catch (error) {
// //         console.error('Error updating data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });


// // app.delete('/profile/:id', async (req, res) => {
// //     const id = req.params.id; // Retrieve the ID parameter from the request URL

// //     try {
// //         const conn = await getConnection ();
// //         // Execute the SQL query to delete data
// //         const result = await conn.query("DELETE FROM taskk.person WHERE id = ?",
// //             [id]);

// //         // Release the connection back to the pool
// //         conn.release();

// //         // Check if any rows were affected by the delete operation
// //         if (result.affectedRows === 0) {
// //             return res.status(404).json({ error: 'Data not found' });
// //         }

// //         // Send response indicating success
// //         res.status(200).json({ message: 'Data deleted successfully' });
// //     } catch (error) {
// //         console.error('Error deleting data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     }
// // });



// // app.post('/api/details', async (req, res) => {
// //     const { decisionName, decisionReason, created_by, user_Creation, user_Statement, tags } = req.body;
// //     let conn;
// //     console.log('bbb')
// //     try {
// //         conn = await getConnection();
// //         await conn.beginTransaction();

// //         // Convert ISO 8601 datetime string to MySQL datetime format
// //         const formattedDateTime = new Date(user_Creation).toISOString().slice(0, 19).replace('T', ' ');

// //         // Insert decision data
// //         const decisionResult = await conn.query(
// //             "INSERT INTO techcoach_lite.decision (decisionName, decisionReason, created_by, user_Creation, user_Statement) VALUES (?, ?, ?, ?, ?)",
// //             [decisionName, decisionReason, created_by, formattedDateTime, user_Statement]
// //         );

// //         const decisionId = decisionResult.insertId;

// //         // Ensure tags is always an array
// //         const tagsArray = Array.isArray(tags) ? tags : (typeof tags === 'string' ? tags.split(',') : []);

// //         // Insert tags and associate them with the decision
// //         for (const tagName of tagsArray) {
// //             // Check if the tag already exists in the database
// //             const tagResult = await conn.query(
// //                 "insert into  techcoach_lite.tag (tag_name) VALUES (?)",
// //                 [tagName]
// //             );

// //             let tagId= tagResult.insertId
// //             // Associate the tag with the decision
// //             await conn.query(
// //                 "INSERT INTO techcoach_lite.decision_tag (decision_id, tag_id) VALUES (?, ?)",
// //                 [decisionId, tagId]
// //             );
// //         }

// //         await conn.commit();
// //         res.status(200).json({ message: 'Data inserted successfully' });
// //     } catch (error) {
// //         console.error('Error inserting data:', error);
// //         if (conn) {
// //             await conn.rollback();
// //             conn.release();
// //         }
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     } finally {
// //         if (conn) {
// //             conn.release();
// //         }
// //     }
// // });


// // POST method route
// app.post('/api/decisions', async (req, res) => {
//     const { decisionName, decisionReason, created_by, user_Creation, user_Statement, tags } = req.body;
//     let conn;
//     try {
//         const conn = await pool.getConnection();

//         await conn.beginTransaction();

//         // Insert the decision into the 'decision' table
//         const decisionInsert = await conn.query(`
//             INSERT INTO techcoach_lite.decisionn (decisionName, decisionReason, created_by, user_Creation, user_Statement) 
//             VALUES (?, ?, ?, ?, ?)`,
//             [decisionName, decisionReason, created_by, user_Creation, user_Statement]
//         );

//         const decisionId = decisionInsert.insertId;

//         // Insert the decision-tag associations into the 'decision_tag' table
//         for (const tag of tags) {
//             await conn.query(`INSERT INTO techcoach_lite.decision_tag (decision_id, tag_id) VALUES (?, (SELECT techcoach_lite.tag_id FROM techcoach_lite.tag WHERE tag_name = ?))`, [decisionId, tag]);
//         }

//         // Commit the transaction
//         await conn.commit();

//         // Release the connection back to the pool
//         conn.release();

//         res.status(200).send('Decision created successfully');
//     } catch (err) {
//         console.error('Error executing SQL query:', err);
//         if (conn) {
//             // Rollback the transaction if an error occurred
//             await conn.rollback();
//             conn.release();
//         }
//         res.status(500).send('Internal Server Error');
//     }
// });





// // app.get('/api/all-decisions', async (req, res) => {
// //     let conn;

// //     try {
// //         conn = await getConnection();

// //         const query = `
// //             SELECT d.*, GROUP_CONCAT(t.tag_name) AS tags
// //             FROM loginn.decision d
// //             JOIN loginn.decision_tag dt ON d.decision_id = dt.decision_id
// //             JOIN loginn.tag t ON dt.tag_id = t.tag_id
// //             GROUP BY d.decision_id
// //         `;

// //         const rows = await conn.query(query);
// //         console.log(rows)

// //         res.status(200).json({a:rows});
// //     } catch (error) {
// //         console.error('Error retrieving data:', error);
// //         res.status(500).json({ error: 'An error occurred while processing your request' });
// //     } finally {
// //         if (conn) {
// //             conn.release();
// //         }
// //     }
// // });



// // app.get('/api/all-decisions', async (req, res) => {
// //     let conn;

// //     try {
// //         conn = await getConnection();

// //         // Query to retrieve all decisions
// //         const decisions = await conn.query(
// //             "SELECT * FROM loginn.decision"
// //         );

// //         // Query to retrieve tags associated with each decision
// //         for (const decision of decisions) {
// //             const tags = await conn.query(
// //                 "SELECT t.tag_name FROM loginn.tag t INNER JOIN loginn.decision_tag dt ON t.tag_id = dt.tag_id WHERE dt.decision_id = ?",
// //                 [decision.decision_id]
// //             );
// //             decision.tags = tags.map(tag => tag.tag_name);
// //         }

// //         res.status(200).json(decisions);
// //     } catch (error) {
// //         console.error('Error fetching decisions:', error);
// //         res.status(500).json({ error: 'An error occurred while fetching decisions' });
// //     } finally {
// //         if (conn) {
// //             conn.release();
// //         }
// //     }
// // });

// app.get('/api/all-decisions', async (req, res) => {
//     let conn;
//     console.log('aa')
//     try {
//         conn = await getConnection();

//         // Retrieve all decision details
//         const decisionData = await conn.query(
//             "SELECT d.*, GROUP_CONCAT(t.tag_name) AS tags " +
//             "FROM techcoach_lite.decision d " +
//             "LEFT JOIN techcoach_lite.decision_tag dt ON d.decision_id = dt.decision_id " +
//             "LEFT JOIN techcoach_lite.tag t ON dt.tag_id = t.tag_id " +
//             "GROUP BY d.decision_id"
//         );

//         // Send the decision data as response
//         res.status(200).json(decisionData);
//     } catch (error) {
//         console.error('Error fetching data:', error);
//         res.status(500).json({ error: 'An error occurred while processing your request' });
//     } finally {
//         if (conn) {
//             conn.release();
//         }
//     }
// });




// app.get('/api/details/:decisionId', async (req, res) => {
//     const { decisionId } = req.params;
//     let conn;

//     try {
//         conn = await getConnection();

//         // Retrieve decision details for the specific decision ID
//         const decisionData = await conn.query(
//             `SELECT d.*, GROUP_CONCAT(t.tag_name) AS tags
//             FROM techcoach_lite.decision d
//             LEFT JOIN techcoach_lite.decision_tag dt ON d.decision_id = dt.decision_id
//             LEFT JOIN techcoach_lite.tag t ON dt.tag_id = t.tag_id
//             WHERE d.decision_id = ?
//             GROUP BY d.decision_id`,
//             [decisionId]
//         );

//         // Check if decisionData is defined and not empty
//         if (!decisionData || decisionData.length === 0) {
//             console.error('Decision not found for ID:', decisionId);
//             return res.status(404).json({ error: 'Decision not found' });
//         }

//         res.status(200).json(decisionData[0]);
//     } catch (error) {
//         console.error('Error fetching data:', error);
//         res.status(500).json({ error: 'An error occurred while processing your request' });
//     } finally {
//         if (conn) {
//             conn.release();
//         }
//     }
// });



// // PUT method
// app.put('/api/details/:decisionId', async (req, res) => {
//     const { decisionId } = req.params;
//     const { decisionName, decisionReason, created_by, user_Creation, user_Statement, tags } = req.body;
//     let conn;
//     console.log('eee')
//     try {
//         conn = await getConnection();
//         await conn.beginTransaction();

//         // Convert ISO 8601 datetime string to MySQL datetime format
//         const formattedDateTime = new Date(user_Creation).toISOString().slice(0, 19).replace('T', ' ');

//         // Update decision data
//         await conn.query(
//             "UPDATE techcoach_lite.decision SET decisionName = ?, decisionReason = ?, created_by = ?, user_Creation = ?, user_Statement = ? WHERE decision_id = ?",
//             [decisionName, decisionReason, created_by, formattedDateTime, user_Statement, decisionId]
//         );

//         // Delete existing associated tags
//         await conn.query(
//             "DELETE FROM techcoach_lite.decision_tag WHERE decision_id = ?",
//             [decisionId]
//         );

//         // Ensure tags is an array before iterating over it
//         const tagsArray = Array.isArray(tags) ? tags : (typeof tags === 'string' ? tags.split(',') : []);
//         for (const tagName of tagsArray) {
//             try {
//                 // Attempt to insert the tag
//                 const tagResult = await conn.query(
//                     "INSERT INTO techcoach_lite.tag (tag_name) VALUES (?)",
//                     [tagName]
//                 );

//                 const tagId = tagResult.insertId;

//                 // Associate the newly inserted tag with the decision
//                 await conn.query(
//                     "INSERT INTO techcoach_lite.decision_tag (decision_id, tag_id) VALUES (?, ?)",
//                     [decisionId, tagId]
//                 );
//             } catch (tagError) {
//                 if (tagError.code === 'ER_DUP_ENTRY') {
//                     // Handle duplicate entry error
//                     console.log(`Tag '${tagName}' already exists. Skipping insertion.`);
//                     // You can retry the operation with a modified tag name here if needed
//                 } else {
//                     // Handle other errors
//                     console.error('Error handling tag:', tagError);
//                     await conn.rollback();
//                     conn.release();
//                     return res.status(500).json({ error: 'An error occurred while processing your request' });
//                 }
//             }
//         }

//         await conn.commit();
//         res.status(200).json({ message: 'Decision updated successfully' });
//     } catch (error) {
//         console.error('Error updating decision:', error);
//         if (conn) {
//             await conn.rollback();
//             conn.release();
//         }
//         res.status(500).json({ error: 'An error occurred while processing your request' });
//     } finally {
//         if (conn) {
//             conn.release();
//         }
//     }
// });


// // DELETE method
// app.delete('/api/details/:id', async (req, res) => {
//     const decisionId = req.params.id;
//     let conn;

//     try {
//         conn = await getConnection();
//         await conn.beginTransaction();

//         // Delete associated tags
//         await conn.query(
//             "DELETE FROM techcoach_lite.decision_tag WHERE decision_id = ?",
//             [decisionId]
//         );

//         // Delete decision
//         await conn.query(
//             "DELETE FROM techcoach_lite.decision WHERE decision_id = ?",
//             [decisionId]
//         );

//         await conn.commit();
//         res.status(200).json({ message: 'Data deleted successfully' });
//     } catch (error) {
//         console.error('Error deleting data:', error);
//         if (conn) {
//             await conn.rollback();
//             conn.release();
//         }
//         res.status(500).json({ error: 'An error occurred while processing your request' });
//     } finally {
//         if (conn) {
//             conn.release();
//         }
//     }
// });


const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('./Middleware/passportConfig');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const decisionRoutes = require('./routes/decisionRoutes');
require('dotenv').config();

const app = express();
const PORT = 6005;

app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.use(morgan('tiny'));
app.use(session({
    secret: 'cats',
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

app.use('/', authRoutes);
app.use('/', userRoutes);
app.use('/api', decisionRoutes);



app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

