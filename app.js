require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");

// Authentication Packages
// --> Level 2 --> ENCRYPTION
// const encrypt = require("mongoose-encryption");
// --> Level 3  --> HASHING
// const md5 = require("md5");
// --> Level 4 --> BCRYPT + SALT ROUNDS
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// --> Level 5 --> Passport.js w/ Local Strategy
// --> Level 6 --> Passport.js w/ Google Strategy
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); // <--- Passport Strategy
const GoogleStrategy = require("passport-google-oauth20").Strategy; // <--- Google Passport Strategy

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(
  session({
    secret: "KevinBryan",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  age: Number,
  country: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// --  Level 2 Authentication -- Encryption

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (user, done) {
  done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.route("/auth/google").get(
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, users) {
    if (err) {
      console.log(err);
    } else {
      if (users) {
        res.render("secrets", { userWithSecrets: users });
      }
    }
  });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user._id, function (err, foundUser) {
    if (!err) {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        console.log(submittedSecret);
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", function (req, res) {
  User.register(
    {
      username: req.body.username,
      age: 19,
      country: "Indonesia",
    },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );

  // // --  Level 4 Authentication -- Bcrypt + Salt Rounds
  // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     // --  Level 3 Authentication -- Hashing
  //     // password: md5(req.body.password),
  //     password: hash,
  //   });
  //   newUser.save(function (err) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    passwoerd: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });

  // const username = req.body.username;
  // const password = req.body.password;
  // User.findOne({ email: username }, function (err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function (err, result) {
  //         console.log("VALIDATING PASSWORD...");
  //         if (err) {
  //           console.log(err);
  //         }
  //         if (result) {
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });
});

app.route("/logout").get(function (req, res) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, function (req, res) {
  console.log("Server started on port 3000.");
});
