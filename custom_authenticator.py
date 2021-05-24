# CustomAuthenticator class.

import hmac, base64, struct, hashlib, time


class CustomAuthenticator:
    '''
    CustomAuthenticator: implements Authenticator similar to Google Authenticator.
    HOTP : HMAC-based One-Time Password. Follows RFC-4226
    TOTP : Time-based One-Time Password.

    Sample output:
        Running Authenticator...
        Sample TOTP token :
        1 402109

        Sample HOTP tokens :
        1 176673
        2 644839
        3 640773
        4 52947
        5 655463
        6 926166
        7 273734
        8 108335
        9 968545

    '''

    def get_hotp_token_with_intervals(self, secret, intervals_no):
        key = base64.b32decode(secret, True)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
        return h


    def get_totp_token(self, secret):
        '''
        Generates time-based token changed in 30-second intervals.
        :param secret: key known to server and Google Authenticator app.
        :return: time-based token changed in 30-second intervals
        '''
        intervals_no = int(time.time())// 30
        return self.get_hotp_token_with_intervals(secret, intervals_no)


    def xrange(self, x, y):
        ''' Implements Python 2's xrange function in Python 3.'''
        return iter(range(x, y))


if __name__ == '__main__':
    print(f'Running Authenticator...')
    authenticator: CustomAuthenticator = CustomAuthenticator()
    secret = 'WXZP363XN6ZX3XWZ'

    print(f'Sample TOTP token :')
    result_index = 1
    print(result_index, authenticator.get_totp_token(secret))
    print()
    print(f'Sample HOTP tokens :')
    for result_index in authenticator.xrange(1, 10):
        print(result_index, authenticator.get_hotp_token_with_intervals(secret, result_index))
