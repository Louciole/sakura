import datetime

class Response:
    CODES = {200: "200 OK", 400: "400 Bad Request", 403: "403 Forbidden", 404: "404 Not Found", 500: "500 Server Error", 302: "302 Redirect"}
    ERROR_PAGES = {}

    def __init__(self, start_response, code=200, type="html"):
        self.cookies = {}
        self.type = type
        self.headers = [('Content-Type', 'text/' + type),('Cache-Control', 'no-cache'), ('Server', 'mag v1 Harpie')]
        self.code = code
        self.start_response = start_response
        self.content = ""

    def ok(self):
        if self.code != 200 and self.code != 302:
            if self.code in self.ERROR_PAGES.keys():
                self.type = "html"
                self.headers = [('Content-Type', 'text/html')]
                file = open(self.ERROR_PAGES[self.code])
                self.content = file.read()
                file.close()
            else:
                self.type = "plain"
                self.headers = [('Content-Type', 'text/plain')]
        self.start_response(self.CODES.get(self.code, "500 UNEXPECTED"), self.headers)

    def encode(self):
        # print("[INFO] encoding response : ", self.content)

        if self.type == "plain":
            return (self.CODES[self.code] + " " + self.content).encode()
        return str(self.content).encode()

    def set_cookie(self, name, value, exp=None, samesite=None, secure=False, httponly=False):
        """Set a response cookie for the client.
        name
            the name of the cookie.

        exp
            the expiration timeout for the cookie. If 0 or other boolean
            False, no 'expires' param will be set, and the cookie will be a
            "session cookie" which expires when the browser is closed.

        samesite
            The 'SameSite' attribute of the cookie. If None (the default)
            the cookie 'samesite' value will not be set. If 'Strict' or
            'Lax', the cookie 'samesite' value will be set to the given value.

        secure
            if False (the default) the cookie 'secure' value will not
            be set. If True, the cookie 'secure' value will be set (to 1).

        httponly
            If False (the default) the cookie 'httponly' value will not be set.
            If True, the cookie 'httponly' value will be set (to 1).

        """

        # Calculate expiration time
        expires = None
        if exp:
            if exp['unit'] == "days":
                expires = datetime.datetime.now() + datetime.timedelta(days=exp['value'])
            elif exp['unit'] == "minutes":
                expires = datetime.datetime.now() + datetime.timedelta(minutes=exp['value'])
            expires = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")

        # Construct cookie string
        cookie_parts = [f"{name}={value}"]
        if expires:
            cookie_parts.append(f"Expires={expires}")
        if samesite:
            cookie_parts.append(f"SameSite={samesite}")
        if secure:
            cookie_parts.append("Secure")
        if httponly:
            cookie_parts.append("HttpOnly")
        cookie_string = "; ".join(cookie_parts)

        # Add cookie to headers
        self.headers.append(('Set-Cookie', cookie_string))

    def del_cookie(self, name):
        self.set_cookie(name, "", exp={"value": 0, "unit": "days"})
