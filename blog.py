import hashlib
import hmac
import os
import random
import re
from string import letters

import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'gmVEvLany0Wo8JDlGobsBOUwgTeC'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))


class generics():
    LOGGEDIN = False
    USERNAME = ""


class MainPage(BlogHandler):
    def get(self):
        if generics.LOGGEDIN:
            self.redirect('profile?username=' + str(generics.USERNAME))
        else:
            self.logout()
            self.render('home.html')


# blog stuff
"""blog models and actions"""

"""helper methods"""


def likes_count(post_id):
    likes = Likes.all().order('-created').filter('liked =', "true")
    likes.filter('post_id =', str(post_id))
    return likes.count()


def comments_count(post_id):
    comments = Comments.all().order('created')
    comments.filter('post_id =', str(post_id))
    return comments.count()


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


"""Posts model and actions"""


class Post(db.Model):
    username = db.StringProperty(required=True)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_username(cls, username):
        # u = db.GqlQuery("SELECT *
        # FROM Post WHERE username = :1", username).get()
        u = Post.all().order('-created').filter('username =', username)
        return u


class AddPost(BlogHandler):
    def get(self):
        if generics.LOGGEDIN:
            self.render('addpost.html')
        else:
            self.render('home.html')

    def post(self):
        have_error = False
        self.title = self.request.get('title')
        self.contnet = self.request.get('content')

        if self.title.strip() and self.contnet.strip():
            have_error = False
        else:
            have_error = True

        if have_error:
            msg = 'Title and Content are required.'
            self.render('addpost.html', error=msg)
        else:
            post = Post(parent=blog_key(),
                        username=generics.USERNAME, title=self.title,
                        content=self.contnet.replace('\n', '<br>'))
            post.put()
            self.redirect('profile?username=' + str(generics.USERNAME))


class EditPost(BlogHandler):
    def get(self, key):
        if generics.LOGGEDIN:
            mykey = key
            key = db.Key.from_path('Post', int(mykey), parent=blog_key())
            post = db.get(key)
            self.render('editpost.html', post=post)
        else:
            self.render('home.html')

    def post(self):
        have_error = False
        mykey = self.request.get('name')
        self.title = self.request.get('title')
        self.contnet = self.request.get('content')

        if self.title.strip() and self.contnet.strip():
            have_error = False
        else:
            have_error = True

        if have_error:
            msg = 'Title and Content are required.'
            self.render('editpost.html', error=msg)
        else:
            key = db.Key.from_path('Post', int(mykey), parent=blog_key())
            post = db.get(key)
            post.title = self.title
            post.content = self.contnet
            post.put()
            self.redirect('profile?username=' + str(generics.USERNAME))


class DeletePost(BlogHandler):
    def get(self, key):
        if generics.LOGGEDIN:
            mykey = key
            key = db.Key.from_path('Post', int(mykey), parent=blog_key())
            db.get(key).delete()
            self.redirect('/profile?username=' + str(generics.USERNAME))
        else:
            self.render('home.html')


class Posts(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        username = str(generics.USERNAME)
        self.render('posts.html', posts=posts, username=username)


class SinglePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        username = str(generics.USERNAME)
        liked = Likes.all().order('-created').filter('liked =', "true")
        liked.filter('username =', str(generics.USERNAME))
        liked.filter('post_id =', str(post_id))
        liked_result = liked.get()

        comments = Comments.all().order('created')
        comments.filter('post_id =', str(post_id))
        self.render('post.html',
                    post=post, username=username,
                    likes_count=likes_count(post_id),
                    comments_count=comments_count(post_id),
                    liked=liked_result,
                    comments=comments)


"""likes model and actions"""


def likes_key(name='default'):
    return db.Key.from_path('likes', name)


class Likes(db.Model):
    username = db.StringProperty(required=True)
    liked = db.StringProperty(required=False)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Like(BlogHandler):
    def get(self, post_id):
        if generics.LOGGEDIN:
            liked = Likes.all().order('-created').filter('liked =', "true")
            liked.filter('username =', str(generics.USERNAME))
            liked.filter('post_id =', str(post_id))
            result = liked.get()
            if result:
                if result.liked == "true":
                    result.liked = "false"
                else:
                    result.liked = "true"
                result.put()
            else:
                like = Likes(parent=likes_key(),
                             username=generics.USERNAME,
                             liked="true", post_id=post_id)
                like.put()

            self.redirect('/post/' + str(post_id))
        else:
            self.redirect('/')


"""comments model and actions"""


def comments_key(name='default'):
    return db.Key.from_path('comments', name)


class Comments(db.Model):
    username = db.StringProperty(required=True)
    content = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Comment(BlogHandler):
    def post(self, post_id):
        if generics.LOGGEDIN:
            comment = Comments(parent=comments_key(),
                               username=generics.USERNAME,
                               content=self.request.get('content').
                               replace('\n', '<br>'),
                               post_id=post_id)
            comment.put()
            self.redirect('/post/' + str(post_id))
        else:
            self.redirect('/')


# user stuff
"""user models and actions"""

"""helper CONSTANTS"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

"""helper methods"""


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def valid_username(username):
    return username and USER_RE.match(username)


def valid_name(name):
    return name and NAME_RE.match(name)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_repassword(password, repassword):
    return password == repassword


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def users_key(group='default'):
    return db.Key.from_path('users', group)


"""user model and actions"""


class Users(db.Model):
    username = db.StringProperty(required=True)
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id(uid, parent=users_key())

    @classmethod
    def by_username(cls, username):
        # u = db.GqlQuery("SELECT *
        # FROM Users WHERE username = :1", username).get()
        u = Users.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, name, pw, email):
        pw_hash = make_pw_hash(username, pw)
        return Users(parent=users_key(),
                     username=username,
                     name=name,
                     pw_hash=pw_hash,
                     email=email)

    @classmethod
    def login(cls, username, pw):
        u = cls.by_username(username)
        if u and valid_pw(username, pw, u.pw_hash):
            return u


class Profile(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if username != generics.USERNAME:
            username = generics.USERNAME
        u = db.GqlQuery("SELECT * "
                        "FROM Users WHERE username = :1", username).get()
        posts = Post.by_username(username)
        privs = True
        if valid_username(username) and u:
            self.render('profile.html', user=u, posts=posts, privs=privs)
        else:
            self.redirect('/')


class Signup(BlogHandler):
    def get(self):
        if generics.LOGGEDIN:
            self.redirect('profile?username=' + str(generics.USERNAME))
        else:
            self.redirect('/')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.firstname = self.request.get('firstname')
        self.lastname = self.request.get('lastname')
        self.password = self.request.get('password')
        self.repassword = self.request.get('repassword')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        if not valid_name(self.firstname):
            params['firstname_error'] = "That's not a valid first name."
            have_error = True

        if not valid_password(self.password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True

        if not valid_repassword(self.password, self.repassword):
            params['repassword_error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('home.html', **params)
        else:
            user = Users.by_username(self.username)

            if user:
                msg = 'That user already exists.'
                self.render('home.html', username_error=msg)
            else:
                fullname = str(self.firstname) + " " + str(self.lastname)
                user = Users.register(username=self.username,
                                      name=fullname,
                                      pw=self.password,
                                      email=self.email)
                user.put()
                self.login(user)
                generics.LOGGEDIN = True
                generics.USERNAME = str(user.username)
                self.redirect('profile?username=' + str(user.username))


class Login(BlogHandler):
    def get(self):
        if generics.LOGGEDIN:
            self.redirect('profile?username=' + str(generics.USERNAME))
        else:
            self.render('home.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = Users.login(username, password)
        if u:
            self.login(u)
            generics.LOGGEDIN = True
            generics.USERNAME = str(u.username)
            self.redirect('profile?username=' + str(u.username))
        else:
            msg = 'Invalid login'
            self.render('home.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        generics.LOGGEDIN = False
        generics.USERNAME = ""
        self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/profile', Profile),
    ('/addpost', AddPost),
    ('/editpost', EditPost),
    ('/editpost/([0-9]+)', EditPost),
    ('/deletepost', DeletePost),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/posts', Posts),
    ('/post/([0-9]+)', SinglePost),
    ('/like/([0-9]+)', Like),
    ('/comment/([0-9]+)', Comment),
],
    debug=True)
