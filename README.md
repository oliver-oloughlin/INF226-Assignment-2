# Assignment 2 A+B

## Initial issues and security concerns

Firstly, the secret key should preferably be an environment variable to keep it more secure, and to avoid it being
included in the git repository.

Secondly, there is initially no security measures implemented regarding password safety, as passwords are stored
in plaintext and are hard coded in to the program itself, instead of residing in a database. There is also no
logic implemented for checking submitted passwords against stored passwords. There likely exists some good packages for hashing, salting and comparing passwords, so I will be searching for an implementation of Bcrypt or similar solutions.

Furthermore, it seems cumbersome that all routes and logic exist in one file, app.py. I will be exploring if
it is possible to devide this up into seperate modules that can be fitted together to create the app.

When sending a message, the sender can at any point decide the name of the sender. This might be an intended design,
which additionally creates anonymity amongst users, but could also be confusing and aids in masking oneself as another user.

There also exists a major flaw in the functionality for searching through messages. The program does not escape the search query,
which leaves the database vulnerable to SQL injection attacks. In addition to this, when searching normally, the user is presented
with the entire contents of the database message entities.

Though it is intended to be useful in this case, the program should not expose the actual database queries that are run.
This helps anyone trying to inject malicous SQL in understanding how the user input is handled and what the database query looks like.

<br>

## Tools / Libraries
* Bcrypt - For hasing, salting and comparing passwords
* Decouple - For loading enviornment variables

<br>

## Changes
To start with, I split the code up into seperate modules, namely app, auth, routes and db. This way the code becomes more tidy and easier to work with/maintain. 

I also implemented the logout route in routes.py. To test that this works as intended one can simply log in to the app, navigate to the /logout route, and then see that one is redirected to the login page and can no longer navigate to / without being redirected back to /login.

All storing of user and other data was moved to the SQLite database.

app.py is the entry point for the program, and sets up the neccessary configurations. The secret key is now also stored as a an enviornment variable in a .env file and loaded using decouple. The .env file is set to be ignored by git, to ensure such global variables are kept secure.

```
from flask import Flask
from routes import use_routes
from db import init_db
from decouple import config

# Set up app
app = Flask(__name__)
app.secret_key = config("SECRET")

# Initiate database and routes
init_db()
use_routes(app)
```

db.py now contains helper methods for querying the database, as well as an initiation script which deletes, creates and inserts data into the tables. The query methods that take user input make sure of the inbuilt parameterisation methods instead of using raw query strings. This prevents SQL injection attacks when for example searching among messages. This can be tested by trying to search with the input: "'; SELECT * FROM announcements; --". While this would successfully select and display all announcements before, it now leads to the method throwing an error.

In auth.py I implemented the helper method valid_login which takes a username and password as arguments. A login attempt is now properly validated by first checking that the username corresponds to an existing User entity, and that the inputted password matches the stored hash of the password using bcrypt.

```
def valid_login(username, password):
    user = get_user(username)
    if not user:
        return False

    hash = user[1]
    return bcrypt.checkpw(password.encode(), hash.encode())
```

<br>

## Questions

Anyone who wishes to obtain sensitive user information or perform malicous actions for any personal gain could potentially attack the application.

An attacker could for example exploit the flawed handling of user inputs to extract what should be confindential information from the database. This could result in the leakage of sensitive data, and possibly for the attacker to be able to gain access to other user accounts.

Depending on the amount of insight to the program design the attacker has, there is likely a limit to how much damage they can do. But in this example there are many flaws that open up for multiple attack vectors and easy explotations.

No program is ever 100% failproof or secure, and as such there is always more that can be done. Therefore one should follow well established guidelines for security, and involving more people to test and look at the code for vulnerabilities is always a good idea.

There are still remaining issues. I haven't changed the actual values for the users. This leaves them havign the passwords "password123" and "bananas", both of which are terribly insecure passwords which a secure program should never let a user choose. Furthermore, it is probably not a great idea to send the plaintext password from users over the network to the server on login (or sign up) requests. Preferably the password should be hashed (without salt, as it needs to be comparable) prior to it ever leaving the users client.

