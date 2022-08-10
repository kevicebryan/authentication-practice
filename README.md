# authentication-practice

## this repo contains how authentication can be done from level 1 to level 6

### Level 1
> Password and Username


this is done by checking if the entered password is equal to the password stored in the database, based on the username queried.


### Level 2
> Encryptioon


the password stored in the database is encrypted, and then decrypted during the checking stage.
```javascript
const encrypt = require("mongoose-encryption");

userSchema.plugin(encrypt, {
  secret: process.env.SECRET,
  encryptedFields: ["password"],
});
```
the secret is kept on a .env file, this SECRET is the key to encrypt/decrypt the password. For logging in just loop through databse, and compare the password, the plugin applied to the userSchema will do the work.


### Level 3
> Hashing


the password is hashed using a hash function, causing it to be changed to a random string, using hash, since it is more difficult to unhash the passowrd, it is more secure than encryption. The way we can login is by hashing the password we filled and compare it to the the hash passowrd in the database.
```javascript
const md5 = require("md5"); // our hash function
password: md5(req.body.password),
```
later we can do the same as level 1 and 2, which is looping through the databse, finding the the username, and check if the hashed input is the same as the hash inthe database.


### Level 4
> Bcrypt + Salt Rounds
> 
>   Bcrypt will do the hashing, and based ont he salt rounds we set, it will hash the password for that amount of time, with this a hacker needs to know not only the hashing function but also the amount of rounds it is hashed.
```javascript
const bcrypt = require("bcrypt");
const saltRounds = 10; // can be hidden in ENV and converted to a Number later...

//Register
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });
    newUser.save(function (err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });

//Logging In
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({ email: username }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          console.log("VALIDATING PASSWORD...");
          if (err) {
            console.log(err);
          }
          if (result) {
            res.render("secrets");
          }
        });
      }
    }
  });
```

### Level 5
> Passport JS -- Local Strategy


using the help of passport, passport-local-mongoose
```javascript
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); // <--- Passport Strategy
const findOrCreate = require("mongoose-findorcreate"); // helper package for findAndCreate function in mongoose

app.use(
  session({
    secret: "KevinBryan",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (user, done) {
  done(null, user);
});

// Register
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
  
// Login
  const user = new User({
    username: req.body.username,
    password: req.body.password,
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

```
with the help of sessions, if user is authenticated and depending to the cookie rule, as long as user is authenticated, informaation that is accesible for autnethicated user are kept, in other words, they won't be logged out immediately when closing the tab.


for more info read this:
[Local Strategy](http://www.passportjs.org/packages/passport-local/)
[Passport Local Mongoose Docs](https://www.npmjs.com/package/passport-local-mongoose)


### Level 6
> Passport JS -- Google Strategy


using OAuth2.0 and the google strategy, we only take the id from google and store it in our db, and google are responsible for the passwowrd checking.
```javascript
const GoogleStrategy = require("passport-google-oauth20").Strategy; // <--- Google Passport Strategy

```

for more info read this:
