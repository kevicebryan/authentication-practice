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
```
later we can do the same as level 1 and 2, which is looping through the databse, finding the the username, and check if the hashed input is the same as the hash inthe database.


### Level 4
> Bcrypt + Salt Rounds
> 
>   Bcrypt will do the hashing, and based ont he salt rounds we set, it will hash the password for that amount of time, with this a hacker needs to know not only the hashing function but also the amount of rounds it is hashed.
```javascript
```

### Level 5
> Passport JS -- Local Strategy


using the help of passport, passport-local-mongoose
```javascript
```

### Level 6
> Passport JS -- Google Strategy


using OAuth2.0 and the google strategy, we only take the id from google and store it in our db, and google are responsible for the passwowrd checking.
```javascript
```
