const express = require("express");
const app = express();

const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());

app.set("view-engine", "ejs"); // to use ejs syntex tell to server
app.use(express.urlencoded({ extended: false }));

const users = [];

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    // console.log(users)
    res.status(400).send("User already exists");
  } else {
    bcrypt.hash(password, 10).then((hash) => {
      try {
        users.push({
          id: Date.now().toString(),
          username: username,
          email: email,
          password: hash,
        });

        console.log(users)

        // res.json("USER REGISTERED");
        res.redirect("/login");
      } catch (err) {
        if (err) {
          res.status(400).json({ error: err });
        }
      }
    });
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  // console.log(user)

  if (!user) res.status(400).json({ error: "User Doesn't Exist" });

  const dbPassword = user.password;
  bcrypt.compare(password, dbPassword).then((match) => {
    if (!match) {
      res
        .status(400)
        .json({ error: "Wrong Username and Password Combination!" });
    } else {
      const accessToken = createTokens(user);

      res.cookie("access-token", accessToken, {
        maxAge: 60 * 60 * 24 * 30 * 1000,
        httpOnly: true,
      });

      console.log("login ",users)
      res.redirect("/profile");

      // res.json("LOGGED IN");
    }
  });
});

app.get("/profile", validateToken, (req, res) => {
  res.render("profile.ejs");
  // res.json("profile");
});

app.get('/logout', function(req, res) {
  res.clearCookie('access-token');
  res.redirect('/login');
});


app.listen(3000, () => {
  console.log("SERVER RUNNING ON PORT 3000");
});
