import base64
import time

import aiohttp
import rsa
from yarl import URL
from pathlib import Path

from steampy import guard
from steampy.models import SteamUrl
from steampy.exceptions import InvalidCredentials, CaptchaRequired


class LoginExecutor:
    def __init__(self, username: str, password: str, shared_secret: str,
                 session: aiohttp.ClientSession):
        self.username = username
        self.password = password
        self.shared_secret = shared_secret
        self.one_time_code = ''
        self.session = session

    async def login(self) -> aiohttp.ClientSession:
        login_response = await self._send_login_request()

        if login_response.get('captcha_needed'):
            raise CaptchaRequired('Captcha required')
        if login_response.get('requires_twofactor'):
            login_response = await self._enter_steam_guard()
        if not login_response['success']:
            raise InvalidCredentials(login_response['message'])

        await self._perform_redirects(login_response)
        self.set_sessionid_cookies()
        return self.session

    async def _send_login_request(self) -> dict:
        rsa_params = await self._fetch_rsa_params()
        encrypted_password = self._encrypt_password(rsa_params)
        rsa_timestamp = rsa_params['rsa_timestamp']
        request_data = self._prepare_login_request_data(
            encrypted_password, rsa_timestamp
        )
        response = await self.session.post(
            SteamUrl.STORE_URL + '/login/dologin',
            data=request_data
        )
        return await response.json()

    def set_sessionid_cookies(self):
        sessionid = self.session.cookie_jar.filter_cookies(
            URL(SteamUrl.HELP_URL)
        ).get('sessionid').value

        self.session.cookie_jar.update_cookies(
            {'sessionid': sessionid}, URL(SteamUrl.COMMUNITY_URL)
        )
        self.session.cookie_jar.update_cookies(
            {'sessionid': sessionid}, URL(SteamUrl.STORE_URL)
        )

    async def _fetch_rsa_params(self, current_number_of_repetitions: int = 0) -> dict:
        maximal_number_of_repetitions = 5
        response = await self.session.post(
            SteamUrl.STORE_URL + '/login/getrsakey/',
            data={'username': self.username}
        )
        response = await response.json()
        try:
            rsa_mod = int(response['publickey_mod'], 16)
            rsa_exp = int(response['publickey_exp'], 16)
            return {'rsa_key': rsa.PublicKey(rsa_mod, rsa_exp),
                    'rsa_timestamp': response['timestamp']}
        except KeyError:
            if current_number_of_repetitions < maximal_number_of_repetitions:
                return await self._fetch_rsa_params(current_number_of_repetitions + 1)
            else:
                raise ValueError('Could not obtain rsa-key')

    def _encrypt_password(self, rsa_params: dict) -> str:
        return base64.b64encode(
            rsa.encrypt(self.password.encode('utf-8'), rsa_params['rsa_key'])
        ).decode('utf-8')

    def _prepare_login_request_data(self, encrypted_password: str, rsa_timestamp: str) -> dict:
        return {
            'password': encrypted_password,
            'username': self.username,
            'twofactorcode': self.one_time_code,
            'emailauth': '',
            'loginfriendlyname': '',
            'captchagid': '-1',
            'captcha_text': '',
            'emailsteamid': '',
            'rsatimestamp': rsa_timestamp,
            'remember_login': 'false',
            'donotcache': str(int(time.time() * 1000))
        }

    async def _enter_steam_guard(self) -> dict:
        self.one_time_code = guard.generate_one_time_code(self.shared_secret)
        return await self._send_login_request()

    async def _perform_redirects(self, login_response: dict) -> None:
        parameters = login_response.get('transfer_parameters')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for url in login_response['transfer_urls']:
            async with self.session.post(url, data=parameters):
                pass
