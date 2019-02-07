class ApiException(Exception):
    pass

class CaptchaRequired(Exception):
    pass

class ConfirmationExpected(Exception):
    pass

class InvalidCredentials(Exception):
    pass

class InvalidSessionPath(Exception):
    pass

class LoginRequired(Exception):
    pass

class SevenDaysHoldException(Exception):
    pass

class TooManyRequests(Exception):
    pass
