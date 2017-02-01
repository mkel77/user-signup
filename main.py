import webapp2
import cgi
import re

page_header = """
<!DOCTYPE html>
<html>
<head>
    <title>Signup</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>
        Signup
    </h1>
"""

page_footer = """
</body>
</html>
"""

form = """
<form method="post">
    <table>
        <tr>
            <td><label for = "Username">Username</label></td>
            <td>
            <input type="text" name="username" value="%(username)s" required>
            <span class="error">%(usernameerror)s</span>
            </td>
        <tr>
            <td><label for = "password">Password</label></td>
            <td>
            <input type="password" name="password" value="%(password)s">
            <span class="error">%(passworderror)s</span>
            </td>
        <tr>
            <td><label for = "verifypassword">Veirfy Password</label></td>
            <td>
            <input type="password" name="verifypassword" value="%(verifypassword)s">
            <span class="error">%(verifypassworderror)s</span>
            </td>
        <tr>
            <td><label for = "email">Email</label></td>
            <td>
            <input type="text" name="email" value="%(email)s"/>
            <span class="error">%(emailerror)s</span>
            </td>
        <tr>
    </table>
        <input type="submit" value="Submit">
</form>
"""
#regular expressions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

class Index(webapp2.RequestHandler):
    def write_form(self, usernameerror="", passworderror="", verifypassworderror="", emailerror="", username="", password="", verifypassword="", email=""):
        self.response.out.write(page_header + page_footer + form % {"usernameerror": usernameerror,
                                                                    "passworderror": passworderror,
                                                                    "verifypassworderror": verifypassworderror,
                                                                    "emailerror": emailerror,
                                                                    "username": username,
                                                                    "password": password,
                                                                    "verifypassword": verifypassword,
                                                                    "email": email})
    def get(self):
        self.write_form()


    def post(self):
        user_username = self.request.get("username")
        user_username = cgi.escape(user_username, quote=True)
        user_password = self.request.get("password")
        user_password = cgi.escape(user_password, quote=True)
        user_verify_password = self.request.get("verifypassword")
        user_verify_password = cgi.escape(user_verify_password, quote=True)
        user_email = self.request.get("email")
        user_email = cgi.escape(user_email, quote=True)


        username_error_element = ""
        password_error_element = ""
        password_didnotmatch_error_element = ""
        email_error_element = ""
        error = False

        if not valid_username(user_username): #username is NOT valid!!!!
            error = True
            username_error_element = "That's not a valid username."

        if not valid_password(user_password): #password is Not valid!!!
            error = True
            password_error_element = "That wasn't a valid password."

        elif not valid_password(user_verify_password) or user_password != user_verify_password:
            error = True
            password_didnotmatch_error_element = "Your passwords didn't match."

        if user_email and not valid_email(user_email):
            error = True
            email_error_element = "That's not a valid email."


        if not error: #both username and password are valid :) :)
            self.redirect("/welcome?username=" + cgi.escape(user_username, quote = True))
        else:
            self.write_form (username_error_element, password_error_element, password_didnotmatch_error_element, email_error_element, user_username, "", "", user_email)

class WelcomePage(webapp2.RequestHandler):

    def get(self):
        new_username = self.request.get("username")
        welcomemessage = "<strong>" + "Welcome, " + new_username + "!" + "</strong>"
        welcomecontent = "<h1>" + welcomemessage + "</h1>" + page_footer
        self.response.write(welcomecontent)

app = webapp2.WSGIApplication([
    ('/signup', Index),
    ('/welcome', WelcomePage)
], debug=True)
