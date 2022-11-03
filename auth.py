from http import HTTPStatus
from flask import abort
from werkzeug.datastructures import WWWAuthenticate
from base64 import b64decode
import flask_login
from db import get_user, get_users
import bcrypt

def valid_login(username, password):
    user = get_user(username)
    if not user:
        return False

    hash = user[1]
    return bcrypt.checkpw(password.encode(), hash.encode())


def use_auth(app):
    # Add a login manager to the app
    login_manager = flask_login.LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"


    # Class to store user info
    # UserMixin provides us with an `id` field and the necessary
    # methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`)
    class User(flask_login.UserMixin):
        pass


    # This method is called whenever the login manager needs to get
    # the User object for a given user id
    @login_manager.user_loader
    def user_loader(username):
        if not get_user(username):
            return

        # For a real app, we would load the User from a database or something
        user = User()
        user.id = username
        return user


    # This method is called to get a User object based on a request,
    # for example, if using an api key or authentication token rather
    # than getting the user name the standard way (from the session cookie)
    @login_manager.request_loader
    def request_loader(request):
        # Even though this HTTP header is primarily used for *authentication*
        # rather than *authorization*, it's still called "Authorization".
        auth = request.headers.get('Authorization')

        # If there is not Authorization header, do nothing, and the login
        # manager will deal with it (i.e., by redirecting to a login page)
        if not auth:
            return

        (auth_scheme, auth_params) = auth.split(maxsplit=1)
        auth_scheme = auth_scheme.casefold()
        if auth_scheme == 'basic':  # Basic auth has username:password in base64
            (username,passwd) = b64decode(auth_params.encode(errors='ignore')).decode(errors='ignore').split(':', maxsplit=1)
            print(f'Basic auth: {username}:{passwd}')
            u = get_user(username)
            if u: # and check_password(u.password, passwd):
                return user_loader(username)
        elif auth_scheme == 'bearer': # Bearer auth contains an access token;
            # an 'access token' is a unique string that both identifies
            # and authenticates a user, so no username is provided (unless
            # you encode it in the token – see JWT (JSON Web Token), which
            # encodes credentials and (possibly) authorization info)
            print(f'Bearer auth: {auth_params}')
            for user in get_users():
                username = user[0]
                token = user[2]
                if token == auth_params:
                    return user_loader(username)
        # For other authentication schemes, see
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

        # If we failed to find a valid Authorized header or valid credentials, fail
        # with "401 Unauthorized" and a list of valid authentication schemes
        # (The presence of the Authorized header probably means we're talking to
        # a program and not a user in a browser, so we should send a proper
        # error message rather than redirect to the login page.)
        # (If an authenticated user doesn't have authorization to view a page,
        # Flask will send a "403 Forbidden" response, so think of
        # "Unauthorized" as "Unauthenticated" and "Forbidden" as "Unauthorized")
        abort(HTTPStatus.UNAUTHORIZED, www_authenticate = WWWAuthenticate('Basic realm=inf226, Bearer'))

    return user_loader