class HTTPRedirect(Exception):
    def __init__(self, response, target):
        response.code = 302
        response.headers.append(('Location', target))
        response.ok()
