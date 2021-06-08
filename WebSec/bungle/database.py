import pymysql as mdb
from bottle import FormsDict
from hashlib import sha256
import os
mysecretkey='38256292cdd2143dbc6abe435a6ef84d2cfd15d54a02fecbd03f5be9b2c1b8ef'
# connection to database project2
def connect():
    """makes a connection to MySQL database.
    @return a mysqldb connection
    """

    #TODO: fill out MySQL connection parameters. Use the netid and password corresponding to the repo you are committing your solution to. 

    return mdb.connect(host="localhost",
                       user="mgg2",
                       passwd=mysecretkey,
                       db="project2");

def createUser(username, password):
    """ creates a row in table named users
    @param username: username of user
    @param password: password of user
    """

    salt = os.urandom(32)
    salted = salt + str.encode(password)

    m = sha256()
    m.update(salted)
    passwordhash = hex(int.from_bytes(m.digest(), byteorder="big"))[2:]
    salt = hex(int.from_bytes(salt, byteorder="big"))[2:]

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO use cur.execute() to insert a new row into the users table containing the username, salt, and passwordhash
    query = """
        INSERT INTO users (username, salt, passwordhash)
        VALUES(%s, %s, %s);
    """
    cur.execute(query, [username, salt, passwordhash]);
    db_rw.commit()

def validateUser(username, password):
    """ validates if username,password pair provided by user is correct or not
    @param username: username of user
    @param password: password of user
    @return True if validation was successful, False otherwise.
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO use cur.execute() to select the appropriate user record (if it exists)
    query = """
        SELECT salt, passwordhash FROM users WHERE username=%s;
        """
    cur.execute(query, [username])
    if cur.rowcount <1:
        return False
    
    user_record = cur.fetchone()
    salt = bytes.fromhex(user_record[0])        # changed this?
    passwordhash_authoritative = user_record[1] # changed this?
    salted = salt + str.encode(password)

    m = sha256()
    m.update(salted)
    passwordhash = hex(int.from_bytes(m.digest(), byteorder="big"))[2:]

    if passwordhash_authoritative == passwordhash:
        return True
    else:
        return False

def fetchUser(username):
    """ checks if there exists given username in table users or not
    if user exists return (id, username) pair
    if user does not exist return None
    @param username: the username of a user
    @return The row which has username is equal to provided input
    """

    db_rw = connect()
    cur = db_rw.cursor(mdb.cursors.DictCursor)
    #TODO use cur.execute() to fetch the row with this username from the users table, if it exists
    query = """
        SELECT id, username
        FROM users
        WHERE username=%s;
    """
    cur.execute(query, username)
    if cur.rowcount < 1:
        return None    
    return FormsDict(cur.fetchone())

def addHistory(user_id, query):
    """ adds a query from user with id=user_id into table named history
    @param user_id: integer id of user
    @param query: the query user has given as input
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO use cur.execute() to add a row to the history table containing the correct user_id and query
    prepstmt = """
        INSERT INTO history (user_id, query)
        VALUES (%s, %s);
    """
    cur.execute(prepstmt, [user_id, query])
    db_rw.commit()

def getHistory(user_id):
    """ grabs last 15 queries made by user with id=user_id from
    table named history in descending order of when the searches were made
    @param user_id: integer id of user
    @return a first column of a row which MUST be query
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO use cur.execute() to fetch the most recent 15 queries from this user (including duplicates). (Make sure the query text is at index 0 in the returned rows)
    query = """
        SELECT query
        FROM history
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 15;
        """
    cur.execute(query, user_id)
    rows = cur.fetchall();
    return [row[0] for row in rows]
