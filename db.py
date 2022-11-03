import sys
import apsw
from apsw import Error
import bcrypt

conn = apsw.Connection('./tiny.db')

def get_users():
  users = conn.execute("SELECT * FROM users;")
  return users

def get_user(username):
  users = conn.execute(f"SELECT * FROM users WHERE username = ?", (username))
  for user in users:
    return user

def get_announcements():
  announcements = conn.execute("SELECT * FROM announcements;")
  return announcements

def search_messages(search):
  messages = conn.execute(f"SELECT * FROM messages WHERE message GLOB ?", (search))
  return messages

def add_message(sender, message):
  conn.execute(f"INSERT INTO messages (sender, message) values (?, ?);", (sender, message))

def init_db():
  try:
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS messages;")
    c.execute("DROP TABLE IF EXISTS announcements;")
    c.execute("DROP TABLE IF EXISTS users;")

    c.execute('''CREATE TABLE IF NOT EXISTS messages (
      id integer PRIMARY KEY, 
      sender TEXT NOT NULL,
      message TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
      id integer PRIMARY KEY, 
      author TEXT NOT NULL,
      text TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      token TEXT);''')

    c.execute("INSERT INTO announcements (text, author) VALUES ('Welcoming announcement', 'Bob')")

    pass1 = bcrypt.hashpw("password123".encode("utf8"), bcrypt.gensalt()).decode("utf8")
    pass2 = bcrypt.hashpw("bananas".encode("utf8"), bcrypt.gensalt()).decode("utf8")
    c.execute(f'''INSERT INTO users VALUES 
    ("alice", "{pass1}", "tiktok"),
    ("bob", "{pass2}", NULL);''')
  except Error as e:
    print(e)
    sys.exit(1)