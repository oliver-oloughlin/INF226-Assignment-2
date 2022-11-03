from flask import abort, request, send_from_directory, make_response, render_template
import flask
from login_form import LoginForm
from json import dumps
from flask_login import logout_user
from flask import redirect
from apsw import Error
from markupsafe import escape
from flask_login import login_required, login_user
from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import HtmlFormatter
from pygments.filters import NameHighlightFilter, KeywordCaseFilter
from pygments import token
from threading import local
from auth import use_auth, valid_login
from db import get_announcements, search_messages, add_message


tls = local()
cssData = HtmlFormatter(nowrap=True).get_style_defs('.highlight')

def pygmentize(text):
    if not hasattr(tls, 'formatter'):
        tls.formatter = HtmlFormatter(nowrap = True)
    if not hasattr(tls, 'lexer'):
        tls.lexer = SqlLexer()
        tls.lexer.add_filter(NameHighlightFilter(names=['GLOB'], tokentype=token.Keyword))
        tls.lexer.add_filter(NameHighlightFilter(names=['text'], tokentype=token.Name))
        tls.lexer.add_filter(KeywordCaseFilter(case='upper'))
    return f'<span class="highlight">{highlight(text, tls.lexer, tls.formatter)}</span>'

def use_routes(app):
  user_loader = use_auth(app)

  @app.route('/favicon.ico')
  def favicon_ico():
      return send_from_directory(app.root_path, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

  @app.route('/favicon.png')
  def favicon_png():
      return send_from_directory(app.root_path, 'favicon.png', mimetype='image/png')


  @app.route('/')
  @app.route('/index.html')
  @login_required
  def index_html():
      return send_from_directory(app.root_path,
                          'index.html', mimetype='text/html')

  @app.route('/login', methods=['GET', 'POST'])
  def login():
      form = LoginForm()
      if form.is_submitted():
          print(f'Received form: {"invalid" if not form.validate() else "valid"} {form.form_errors} {form.errors}')
          print(request.form)
      if form.validate_on_submit():
          username = form.username.data
          password = form.password.data
          success = valid_login(username, password)
          if success:
              user = user_loader(username)
              
              # automatically sets logged in session cookie
              login_user(user)

              flask.flash('Logged in successfully.')

              next = flask.request.args.get('next')
      
              # is_safe_url should check if the url is safe for redirects.
              # See http://flask.pocoo.org/snippets/62/ for an example.
              if False and not is_safe_url(next):
                  return flask.abort(400)

              return flask.redirect(next or flask.url_for('index'))
      return render_template('./login.html', form=form)

  @app.route("/logout")
  @login_required
  def logout():
      logout_user()
      return redirect("/")

  @app.get('/search')
  def search():
      query = request.args.get('q') or request.form.get('q') or '*'
      stmt = f"SELECT * FROM messages WHERE message GLOB '{query}'"
      result = f"Query: {pygmentize(stmt)}\n"
      try:
          messages = search_messages(query)
          result = result + 'Result:\n'
          for msg in messages:
              result = f'{result}    {dumps(msg)}\n'
          return result
      except Error as e:
          return (f'{result}ERROR: {e}', 500)

  @app.route('/send', methods=['POST','GET'])
  def send():
      try:
          sender = request.args.get('sender') or request.form.get('sender')
          message = request.args.get('message') or request.args.get('message')
          if not sender or not message:
              return f'ERROR: missing sender or message'
          stmt = f"INSERT INTO messages (sender, message) values ('{sender}', '{message}');"
          result = f"Query: {pygmentize(stmt)}\n"
          add_message(sender, message)
          return f'{result}ok'
      except Error as e:
          return f'{result}ERROR: {e}'

  @app.get('/announcements')
  def announcements():
      try:
          announcements = get_announcements()
          anns = []
          for ann in announcements:
              anns.append({'sender':escape(ann[1]), 'message':escape(ann[2])})
          return {'data':anns}
      except Error as e:
          return {'error': f'{e}'}

  @app.get('/coffee/')
  def nocoffee():
      abort(418)

  @app.route('/coffee/', methods=['POST','PUT'])
  def gotcoffee():
      return "Thanks!"

  @app.get('/highlight.css')
  def highlightStyle():
      resp = make_response(cssData)
      resp.content_type = 'text/css'
      return resp