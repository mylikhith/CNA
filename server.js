const express = require("express");
const app = express();

const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());

const users = [];

app.post("/register", (req, res) => {
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
          email: req.body.email,
          password: hash,
        });

        // console.log(users)

        res.json("USER REGISTERED");
      } catch (err) {
        if (err) {
          res.status(400).json({ error: err });
        }
      }
    });
  }
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

      res.json("LOGGED IN");
    }
  });
});

app.get("/profile", validateToken, (req, res) => {
  res.json("profile");
});

app.listen(3000, () => {
  console.log("SERVER RUNNING ON PORT 3000");
});
