import base64
import hmac
import struct
import time

from hashlib import sha1


def generate_one_time_code(shared_secret: str, timestamp: int = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    # pack as Big endian, uint64
    time_buffer = struct.pack('>Q', timestamp // 30)
    time_hmac = hmac.new(base64.b64decode(shared_secret),
                         time_buffer, digestmod=sha1).digest()
    begin = ord(time_hmac[19:20]) & 0xf
    # unpack as Big endian uint32
    full_code = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7fffffff
    chars = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        full_code, i = divmod(full_code, len(chars))
        code += chars[i]

    return code

def generate_confirmation_key(identity_secret: str, tag: str,
                              timestamp: int = int(time.time())) -> bytes:
    buffer = struct.pack('>Q', timestamp) + tag.encode('ascii')
    return base64.b64encode(
        hmac.new(
            base64.b64decode(identity_secret), buffer, digestmod=sha1
        ).digest()
    )

# It works, however it's different that one generated from mobile app
def generate_device_id(steam_id: str) -> str:
    hexed_steam_id = sha1(steam_id.encode('ascii')).hexdigest()
    return 'android:' + '-'.join([hexed_steam_id[:8],
                                  hexed_steam_id[8:12],
                                  hexed_steam_id[12:16],
                                  hexed_steam_id[16:20],
                                  hexed_steam_id[20:32]])
