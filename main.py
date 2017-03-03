#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)
secret = 'fartster'


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

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                         % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


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


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw,
                 email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render('signup_form.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup_form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists'
            self.render('signup_form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/blog/login')


class Login(BlogHandler):

    def get(self):
        self.render('login_form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            self.render('login_form.html', username=username,
                        error='Invalid Login')


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog/login')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):

    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    date = db.DateProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author_id = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('front.html', posts=self)


class Likes(db.Model):

    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_author(cls, post_id):
        key = db.GqlQuery('select * from Likes where post = :1',
                          post_id)
        return key.count()

    @classmethod
    def check_likes(cls, post_id, user_id):
        key = Likes.all().filter('post = ', post_id).filter('user = ',
                                                            user_id)
        return key.count()


class Unlikes(db.Model):

    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_author(cls, post_id):
        key = db.GqlQuery('select * from Unlikes where post = :1',
                          post_id)
        return key.count()

    @classmethod
    def check_likes(cls, post_id, user_id):
        key = Unlikes.all().filter('post = ', post_id).filter('user = ',
                                                              user_id)
        return key.count()


class Comments(db.Model):

    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    date = db.DateProperty(auto_now_add=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty()
    author_name = db.StringProperty()

    @classmethod
    def by_author(cls, post_id):
        key = \
            db.GqlQuery('select * from ' +
                        'Comments where post = :1 order by created',
                        post_id)
        return key

    def by_id(cls, uid):
        return Comments.get_by_id(uid, parents=users_key())


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render('new_post.html')
        else:
            self.redirect('/blog/login')

    def post(self):
        if not self.user:
            self.redirect('/blog/login')

        subject = self.request.get('subject')
        blog = self.request.get('blog')
        author = self.user.name

        error_subject = 'Subject Cannot Be Blank Duhh!!'
        error_blog = 'Blank'

        if subject:
            error_subject = ''
        if blog:
            error_blog = ''

        if not subject or not blog:
            self.render('new_post.html', subject=subject, blog=blog,
                        error_subject=error_subject,
                        error_blog=error_blog)
        else:
            p = Post(parent=blog_key(), subject=subject, content=blog,
                     author=author, author_id=str(self.user.key().id()))
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))


class PostPage(BlogHandler):

    def get(self, id):
        if not self.user:
            self.redirect('/blog/login')
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)
        prev_comments = Comments.by_author(post)
        likes = Likes.by_author(post)
        unlikes = Unlikes.by_author(post)
        if post:
            self.render('permalink.html', post=post, likes=likes,
                        unlikes=unlikes, comments=prev_comments)

    def post(self, id):
        user_id = User.by_name(self.user.name)
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)
        likes = Likes.by_author(post)
        unlikes = Unlikes.by_author(post)
        prev_unliked = Unlikes.check_likes(post, user_id)
        prev_liked = Likes.check_likes(post, user_id)
        prev_comments = Comments.by_author(post)

        if not self.user:
            self.redirect('/blog/login')

        if self.request.get('edit'):
            if post.author_id == str(self.user.key().id()):
                self.redirect('/blog/editPost/%s'
                              % str(post.key().id()))
            else:
                self.render(
                    'permalink.html',
                    post=post,
                    error='You cannot edit this post',
                    likes=likes,
                    unlikes=unlikes,
                    comments=prev_comments,
                    )

        if self.request.get('delete'):

            if post.author_id == str(self.user.key().id()):
                self.redirect('/blog/deletepost/%s'
                              % str(post.key().id()))
            else:
                self.render(
                    'permalink.html',
                    post=post,
                    error='You cannot delete this post',
                    likes=likes,
                    unlikes=unlikes,
                    comments=prev_comments,
                    )

        if self.request.get('like'):
            if post.author_id != str(self.user.key().id()):
                if prev_liked == 0:
                    l = Likes(post=post, user=user_id)
                    l.put()
                    time.sleep(0.1)
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    self.render(
                        'permalink.html',
                        post=post,
                        error='You have already liked it',
                        likes=likes,
                        unlikes=unlikes,
                        comments=prev_comments,
                        )
            else:
                self.render(
                    'permalink.html',
                    post=post,
                    error='You cannot like your own post',
                    likes=likes,
                    unlikes=unlikes,
                    comments=prev_comments,
                    )

        if self.request.get('unlike'):
            if post.author_id != str(self.user.key().id()):
                if prev_unliked == 0:
                    l = Unlikes(post=post, user=user_id)
                    l.put()
                    time.sleep(0.1)
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    self.render(
                        'permalink.html',
                        post=post,
                        error='You have already unliked it',
                        likes=likes,
                        unlikes=unlikes,
                        comments=prev_comments,
                        )
            else:
                self.render(
                    'permalink.html',
                    post=post,
                    error='You cannot unlike your own post',
                    likes=likes,
                    unlikes=unlikes,
                    comments=prev_comments,
                    )

        if self.request.get('comment'):
            comment = self.request.get('commentbox')
            if not comment:
                self.render(
                    'permalink.html',
                    post=post,
                    error='You cannot submit a blank comment',
                    likes=likes,
                    unlikes=unlikes,
                    comments=prev_comments,
                    )
            else:
                c = Comments(post=post, user=user_id, comment=comment,
                             author=str(self.user.key().id()),
                             author_name=str(self.user.name))
                c.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(post.key().id()))


class EditComment(BlogHandler):

    def get(self, id):
        key = db.Key.from_path('Comments', int(id))
        comment = db.get(key)
        self.render('editcomment.html', post=comment.post, x=comment)

    def post(self, id):
        key = db.Key.from_path('Comments', int(id))
        comment = db.get(key)

        if self.request.get('editcomment'):

            if str(comment.user.name) != str(self.user.name):
                self.render('editcomment.html', post=comment.post,
                            x=comment, error='Cannot Edit Other Post')
            else:
                editedcomment = self.request.get('commentbox')
                if not editedcomment:
                    self.render('editcomment.html', post=comment.post,
                                x=comment,
                                error='Cannot have a Blank Comment')
                else:
                    comment.comment = editedcomment
                    comment.put()
                    time.sleep(0.1)
                    self.redirect('/blog/%s' % comment.post.key().id())

        if self.request.get('deletecomment'):
            self.write(comment.user)
            if str(comment.user.name) != str(self.user.name):
                self.render('editcomment.html', post=comment.post,
                            x=comment,
                            error='Cannot Delete Others Comment')
            else:
                string = comment.post.key().id()
                comment.delete()
                time.sleep(0.1)
                self.redirect('/blog/%s' % string)

        if self.request.get('cancel'):
            self.redirect('/blog/%s' % comment.post.key().id())


class DeletePost(BlogHandler):

    def get(self, id):
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)

        if self.user and post and post.author_id \
           == str(self.user.key().id()):

            post.delete()
            time.sleep(0.1)
            self.redirect('/blog')
        else:
            self.redirect('/blog/login')


class EditPost(BlogHandler):

    def get(self, id):
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        content = post.content
        self.render('editpost.html', subject=subject, content=content)

    def post(self, id):

        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)

        if not self.user or not post or not post.author_id \
           == str(self.user.key().id()):
            self.redirect('/blog/login')

        subject = self.request.get('subject')
        blog = self.request.get('blog')
        if self.user:
            author = self.user.name
        else:
            self.redirect('/blog/login')

        error_subject = 'Subject Cannot Be Blank Duhh!!'
        error_blog = 'Blank'

        if subject:
            error_subject = ''
        if blog:
            error_blog = ''

        if not subject or not blog:
            self.render('editpost.html', subject=subject, content=blog,
                        error_subject=error_subject,
                        error_blog=error_blog)
        else:
            post.subject = subject
            post.content = blog
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))


class AllPost(BlogHandler):

    def get(self):
        id = self.request.get('id')
        if not id:
            posts = Post.all().order('-created')
            self.render('blogs.html', posts=posts)
        elif id == '1':
            if self.user:
                posts = \
                    db.GqlQuery("SELECT * FROM Post where author = '%s'"
                                % self.user.name)
                self.render('blogs.html', posts=posts)
            else:
                self.redirect('/blog/login')


class MainHandler(BlogHandler):

    def get(self):
        self.redirect('/blog')


class About(BlogHandler):

    def get(self):
        self.render('about.html')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/signup', Register),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/newpost', NewPost),
    ('/blog', AllPost),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/editPost/([0-9]+)', EditPost),
    ('/blog/deletepost/([0-9]+)', DeletePost),
    ('/blog/comment/([0-9]+)', EditComment),
    ('/about', About),
    ], debug=True)
