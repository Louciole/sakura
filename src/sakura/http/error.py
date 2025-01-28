class HTTPError(Exception):
    def __init__(self, response, code=500, message="Unexpected"):
        response.code = code
        response.content = message
        response.ok()
