import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
let currentUser;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(bodyParser.json());
app.use(express.json());

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("front-page.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("landing_page.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const name = req.body.name;
    console.log(email);
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
            [name, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) { 
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        currentUser = user.id;
        console.log(currentUser);
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

//Friends section
app.get("/Fitness-app/views/friends.ejs", (req,res)=>{
  res.render("friends.ejs");
});

app.get("/Fitness-app/views/landing_page.ejs", (req,res)=>{
  res.render("landing_page.ejs");
});

app.get('/api/friends', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM friends WHERE user_id = $1',[currentUser]);
    res.json({ friends: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch friends' });
  }
});

app.get('/api/search', async (req, res) => {
  const query = req.query.query;
  try {
    const result = await db.query('SELECT * FROM users WHERE name ILIKE $1 AND id != $2', [`%${query}%`,currentUser]);
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Add friend
app.post('/api/add-friend', async (req, res) => {
  const userId = req.body.userId;
  console.log(currentUser);
  try {
    const result = await db.query('INSERT INTO friends (user_id, frnd_id, name) SELECT $1, id, name FROM users WHERE id = $2 RETURNING *', [currentUser, userId]);
    res.json({ friend: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add friend' });
  }
});

// Route to create a challenge
app.post('/api/create-challenge', async (req, res) => {
  const { startTime, endTime, noOfPushups, wageAmount, invitedFriends } = req.body;
  const userId = currentUser; // Assume you have middleware to set req.user

  try {
    // Insert challenge into the database
    const result = await db.query(
      'INSERT INTO challenges (user_id, start_time, end_time, no_of_pushups, wage_amount) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [userId, startTime, endTime, noOfPushups, wageAmount]
    );

    const challengeId = result.rows[0].id;

    // Insert each invited friend into challenge_invitations table
    if (invitedFriends.length > 0) {
      const inviteValues = invitedFriends.map(friendId => `(${challengeId}, ${friendId}, 'invited')`).join(',');
      await db.query(`INSERT INTO challenge_invitations (challenge_id, friend_id, status) VALUES ${inviteValues}`);
    }

    res.json({ challenge: result.rows[0] });
  } catch (err) {
    console.error('Failed to create challenge:', err);
    res.status(500).json({ error: 'Failed to create challenge' });
  }
});

// Route to get challenge details
app.get('/api/challenge-details/:id', async (req, res) => {
  const challengeId = req.params.id;
  try {
    const result = await db.query('SELECT * FROM challenges WHERE id = $1', [challengeId]);
    const invitations = await db.query('SELECT * FROM challenge_invitations WHERE challenge_id = $1', [challengeId]);

    res.json({ challenge: result.rows[0], invitations: invitations.rows });
  } catch (err) {
    console.error('Failed to fetch challenge details:', err);
    res.status(500).json({ error: 'Failed to fetch challenge details' });
  }
});

// Route to join a challenge
app.post('/api/join-challenge/:id', async (req, res) => {
  const challengeId = req.params.id;
  const userId = req.user.id; // Assume you have middleware to set req.user

  try {
    await db.query(
      'UPDATE challenge_invitations SET status = $1 WHERE challenge_id = $2 AND friend_id = $3',
      ['joined', challengeId, userId]
    );
    res.json({ message: 'Successfully joined the challenge' });
  } catch (err) {
    console.error('Failed to join challenge:', err);
    res.status(500).json({ error: 'Failed to join challenge' });
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
