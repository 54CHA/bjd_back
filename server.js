require("dotenv").config();
const express = require("express");
const { Pool } = require("pg"); // Import the Pool class from pg
const cors = require("cors");
const bcrypt = require("bcrypt"); // Import bcrypt

const app = express();
const PORT = process.env.PORT || 5001; // Use a different port than the frontend dev server
const SALT_ROUNDS = 10; // Cost factor for bcrypt hashing

// Middleware
app.use(cors()); // Allow requests from the frontend origin
app.use(express.json()); // Parse JSON request bodies

// --- Database Connection (PostgreSQL) ---
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("FATAL ERROR: DATABASE_URL is not defined in .env file.");
  process.exit(1); // Exit if DB connection string is missing
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Optional: Add SSL configuration if required by your PostgreSQL provider
  ssl: { rejectUnauthorized: false },
});

// Test DB connection and create table if not exists
const initializeDatabase = async () => {
  let client;
  try {
    client = await pool.connect();
    console.log("PostgreSQL connected successfully.");

    // SQL to create the scores table if it doesn't exist (use pin_hash)
    await client.query(`
      CREATE TABLE IF NOT EXISTS scores (
        id SERIAL PRIMARY KEY,
        nickname VARCHAR(20) NOT NULL,
        pin_hash VARCHAR(60) NOT NULL, -- Store the bcrypt hash (60 chars)
        score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("'scores' table structure checked/created.");

    // --- Column Rename/Addition Logic (Handle transition from plain pin) ---
    // Check if old 'pin' column exists
    const checkPinCol = await client.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='scores' AND column_name='pin';
    `);

    if (checkPinCol.rowCount > 0) {
      // Old 'pin' column exists, attempt to rename to 'pin_hash'
      // This might fail if 'pin_hash' already exists from a previous run
      try {
        await client.query(`ALTER TABLE scores RENAME COLUMN pin TO pin_hash;`);
        console.log("Renamed old 'pin' column to 'pin_hash'.");
        // Update type AFTER renaming (important for some PG versions)
        try {
          await client.query(
            `ALTER TABLE scores ALTER COLUMN pin_hash TYPE VARCHAR(60);`
          );
          console.log("Changed 'pin_hash' column type to VARCHAR(60).");
        } catch (typeError) {
          console.warn(
            `Could not change pin_hash type (maybe already correct?): ${typeError.message}`
          );
        }
        // **IMPORTANT**: Existing plain text PINs are now in pin_hash!
        // You would ideally need a migration script to hash these.
        console.warn(
          "WARNING: Existing PINs were stored as plain text and are now in 'pin_hash'. They MUST be updated/hashed manually or via a migration script for login to work."
        );
      } catch (renameError) {
        if (renameError.code === "42701") {
          // duplicate_column
          console.log(
            "'pin_hash' column already exists, attempting to drop old 'pin' column if it still exists."
          );
          // If rename fails because pin_hash exists, try dropping the old pin column if it wasn't dropped yet
          try {
            await client.query(`ALTER TABLE scores DROP COLUMN IF EXISTS pin;`);
            console.log("Dropped old 'pin' column as 'pin_hash' exists.");
          } catch (dropError) {
            console.error(
              "Failed to drop old 'pin' column after rename failed:",
              dropError
            );
          }
        } else if (renameError.code !== "42703") {
          // 42703: column undefined (already renamed/dropped)
          console.error("Error renaming 'pin' column:", renameError);
        } else {
          console.log("Old 'pin' column likely already renamed or dropped.");
        }
      }
    } else {
      // Old 'pin' column doesn't exist, check if 'pin_hash' exists
      const checkPinHashCol = await client.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='scores' AND column_name='pin_hash';
         `);
      if (checkPinHashCol.rowCount === 0) {
        // Neither column exists, add pin_hash
        try {
          await client.query(
            `ALTER TABLE scores ADD COLUMN pin_hash VARCHAR(60);`
          );
          console.log("Added 'pin_hash' column.");
        } catch (addError) {
          console.error("Failed to add 'pin_hash' column:", addError);
          throw addError; // Fail init if column cannot be added
        }
      } else {
        // pin_hash already exists
        console.log("'pin_hash' column already exists.");
        // Ensure type is correct
        try {
          await client.query(
            `ALTER TABLE scores ALTER COLUMN pin_hash TYPE VARCHAR(60);`
          );
        } catch (typeError) {
          if (typeError.code !== "42804") {
            // type mismatch (already correct)
            console.warn(
              `Could not change pin_hash type (maybe already correct?): ${typeError.message}`
            );
          } else {
            console.log("'pin_hash' column type likely already correct.");
          }
        }
      }
    }
    // --- End Column Rename/Addition Logic ---

    // Ensure the UNIQUE constraint exists on nickname
    try {
      await client.query(
        `ALTER TABLE scores ADD CONSTRAINT scores_nickname_unique UNIQUE (nickname);`
      );
      console.log("Unique constraint on 'nickname' added or already exists.");
    } catch (constraintError) {
      if (
        constraintError.code === "23505" ||
        constraintError.code === "42710"
      ) {
        // unique_violation or duplicate_object
        console.log("Unique constraint on 'nickname' already exists.");
      } else {
        console.error("Error adding unique constraint:", constraintError);
      }
    }

    console.log("Database schema initialization complete.");
  } catch (err) {
    console.error("Database initialization error:", err);
    process.exit(1); // Exit if critical init fails
  } finally {
    if (client) client.release(); // Release the client back to the pool
  }
};

initializeDatabase(); // Run the initialization

// --- API Routes ---

// GET /api/scores - Retrieve all scores (removed LIMIT 10)
app.get("/api/scores", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nickname, score, created_at FROM scores ORDER BY score DESC" // Removed LIMIT 10
    );
    res.json(result.rows); // Send the rows back as JSON
  } catch (error) {
    console.error("Error fetching scores:", error);
    res.status(500).json({ message: "Error fetching scores" });
  }
});

// POST /api/start_session - Authenticate user or create new user (using bcrypt)
app.post("/api/start_session", async (req, res) => {
  let client;
  try {
    const { nickname, pin } = req.body;

    // --- Input Validation ---
    if (
      !nickname ||
      typeof nickname !== "string" ||
      nickname.trim().length === 0 ||
      nickname.trim().length > 20
    ) {
      return res.status(400).json({ message: "Invalid nickname provided." });
    }
    if (!pin || typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
      return res
        .status(400)
        .json({ message: "Invalid PIN provided (must be exactly 4 digits)." });
    }
    const trimmedNickname = nickname.trim();

    client = await pool.connect();

    // --- Check if user exists ---
    const existingUserResult = await client.query(
      "SELECT id, nickname, pin_hash, score, created_at FROM scores WHERE nickname = $1",
      [trimmedNickname]
    );

    if (existingUserResult.rowCount > 0) {
      // --- User exists: Validate PIN using bcrypt.compare ---
      const userData = existingUserResult.rows[0];
      const isPinValid = await bcrypt.compare(pin, userData.pin_hash);

      if (isPinValid) {
        console.log(`Authentication successful for ${trimmedNickname}`);
        const { pin_hash: _, ...userDataWithoutHash } = userData; // Exclude hash from response
        res.status(200).json({
          message: "Authentication successful",
          user: userDataWithoutHash,
        });
      } else {
        console.log(
          `Authentication failed for ${trimmedNickname}: Incorrect PIN`
        );
        res.status(401).json({ message: "Incorrect PIN provided." });
      }
    } else {
      // --- User does not exist: Create new user with hashed PIN ---
      try {
        const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);
        const insertResult = await client.query(
          "INSERT INTO scores (nickname, pin_hash, score, created_at) VALUES ($1, $2, 0, CURRENT_TIMESTAMP) RETURNING id, nickname, score, created_at",
          [trimmedNickname, hashedPin] // Remove the extra , 0
        );
        console.log(`Created new user ${trimmedNickname}`);
        res.status(201).json({
          message: "User created successfully",
          user: insertResult.rows[0],
        });
      } catch (insertError) {
        // Handle potential race condition
        if (insertError.code === "23505") {
          console.warn(
            `Race condition during user creation for ${trimmedNickname}. Trying lookup again.`
          );
          const raceLookupResult = await client.query(
            "SELECT id, nickname, pin_hash, score, created_at FROM scores WHERE nickname = $1",
            [trimmedNickname]
          );
          if (raceLookupResult.rowCount > 0) {
            const isPinValidOnRace = await bcrypt.compare(
              pin,
              raceLookupResult.rows[0].pin_hash
            );
            if (isPinValidOnRace) {
              const { pin_hash: _, ...userDataWithoutHash } =
                raceLookupResult.rows[0];
              res.status(200).json({
                message: "Authentication successful (after race condition)",
                user: userDataWithoutHash,
              });
            } else {
              res.status(401).json({
                message: "Incorrect PIN provided (race condition resolution).",
              });
            }
          } else {
            res.status(500).json({
              message:
                "Race condition resolution failed - user not found after insert conflict.",
            });
          }
        } else {
          console.error("Error creating new user:", insertError);
          res.status(500).json({ message: "Error creating user" });
        }
      }
    }
  } catch (error) {
    console.error("Error in start_session:", error);
    res
      .status(500)
      .json({ message: "Internal server error during session start." });
  } finally {
    if (client) client.release();
  }
});

// POST /api/scores - Now only UPDATES scores for existing users
app.post("/api/scores", async (req, res) => {
  try {
    const { nickname, score } = req.body;

    // Basic validation
    if (
      !nickname ||
      typeof nickname !== "string" ||
      nickname.trim().length === 0 ||
      nickname.trim().length > 20
    ) {
      return res.status(400).json({ message: "Invalid nickname provided." });
    }
    if (
      typeof score !== "number" ||
      !Number.isInteger(score) ||
      score < 0 ||
      score > 100
    ) {
      return res.status(400).json({
        message:
          "Invalid score provided (must be an integer between 0 and 100).",
      });
    }
    const trimmedNickname = nickname.trim();

    // Update score only if nickname exists and new score is higher
    // No ON CONFLICT needed as user creation is separate
    const updateQuery = `
        UPDATE scores SET
            score = $1,
            created_at = CURRENT_TIMESTAMP
        WHERE nickname = $2 AND score < $1 -- Check nickname and existing score
        RETURNING id, nickname, score, created_at;
    `;

    const result = await pool.query(updateQuery, [score, trimmedNickname]);

    if (result.rowCount > 0) {
      // Score was updated
      console.log(
        `Updated score for ${trimmedNickname} to ${score}. Resulting row:`,
        result.rows[0]
      );
      res.status(200).json(result.rows[0]);
    } else {
      // Nickname not found OR score was not higher. Fetch existing to return.
      console.log(
        `Update condition not met for ${trimmedNickname} with score ${score}. Fetching existing.`
      );
      const existingResult = await pool.query(
        "SELECT id, nickname, score, created_at FROM scores WHERE nickname = $1",
        [trimmedNickname]
      );
      if (existingResult.rowCount > 0) {
        res.status(200).json(existingResult.rows[0]); // Return existing data
      } else {
        // If nickname genuinely doesn't exist (shouldn't happen if session started)
        console.error(
          "Error: Nickname not found during score update attempt:",
          trimmedNickname
        );
        res
          .status(404)
          .json({ message: "Nickname not found for score update." });
      }
    }
  } catch (error) {
    console.error("Error processing score update:", error);
    res.status(500).json({ message: "Error processing score update" });
  }
});

// Basic root route for testing
app.get("/", (req, res) => {
  res.send("Earthquake Survival Backend (PostgreSQL) is running!");
});

// Start the server
app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});
