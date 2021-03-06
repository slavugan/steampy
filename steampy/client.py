import json
import urllib.parse as urlparse
from typing import List, Union, Optional, Tuple, Any
from pathlib import Path

import aiohttp
import bs4
import requests
from yarl import URL

from steampy import guard
from steampy.chat import SteamChat
from steampy.confirmation import ConfirmationExecutor
from steampy.exceptions import (
    ApiException, InvalidSessionPath, LoginRequired, SevenDaysHoldException
)
from steampy.login import LoginExecutor, InvalidCredentials
from steampy.market import SteamMarket
from steampy.models import Asset, TradeOfferState, SteamUrl, GameOptions
from steampy.utils import (
    account_id_to_steam_id,
    get_description_key,
    get_key_value_from_url,
    merge_items_with_descriptions_from_inventory,
    merge_items_with_descriptions_from_offer,
    merge_items_with_descriptions_from_offers,
    price_to_float,
    steam_id_to_account_id,
    text_between,
    texts_between,
)


def login_required(func):
    def func_wrapper(self, *args, **kwargs):
        if not self.was_login_executed:
            raise LoginRequired('Use login method first')
        else:
            return func(self, *args, **kwargs)
    return func_wrapper


class SteamClient:
    def __init__(self,
                 username: str = None,
                 password: str = None,
                 api_key: str = None,
                 shared_secret: str = None,
                 identity_secret: str = None,
                 steam_id: str = None,
                 reuse_session: bool = False,
                 session_file: Path = None,
                 sessions_dir: Path = None,
                ) -> None:
        self._api_key = api_key
        self._identity_secret = identity_secret
        self._password = password
        self._shared_secret = shared_secret
        self._session = aiohttp.ClientSession()
        self._api_session = aiohttp.ClientSession()
        self.username = username
        self.steam_id = steam_id
        self.was_login_executed = False
        self.market = SteamMarket(self._session)
        self.chat = SteamChat(self._session)
        self.reuse_session = reuse_session
        self.session_file = session_file
        self.sessions_dir = sessions_dir

    async def login(self) -> None:
        session_loaded = False
        if self.reuse_session:
            session_loaded = await self.load_session()
            if session_loaded:
                print('session loaded')
            elif session_loaded == False:
                print('session is not alive any more')
        if not session_loaded:
            print('do classic login')
            login_executor = LoginExecutor(username=self.username,
                                           password=self._password,
                                           shared_secret=self._shared_secret,
                                           session=self._session)
            await login_executor.login()
        self.was_login_executed = True
        self.market._set_login_executed(steam_id=self.steam_id,
                                        session_id=self._get_session_id(),
                                        identity_secret=self._identity_secret)
        if self.reuse_session:
            self.save_session()

    def save_session(self) -> None:
        if self.session_file and self.session_file.is_file():
            self._session.cookie_jar.save(self.session_file)

    async def load_session(self) -> Optional[bool]:
        try:
            self.set_session_file()
        except InvalidSessionPath as err:
            self.reuse_session = False
            raise err

        if self.session_file.exists():
            print('loading session from file: %s' % self.session_file)
            self._session.cookie_jar.load(self.session_file)
            return await self.is_session_alive()
        print('there is no file to load the sesssion')

    async def close_session(self) -> None:
        """Saves session if needed.
        Closes underlying connector. Releases all acquired resources.
        Call it at the end of your program or when you don't want to use
        this client amy more
        """
        if self.reuse_session:
            self.save_session()
        await self._session.close()
        await self._api_session.close()

    @login_required
    async def logout(self) -> None:
        await self._session.post(SteamUrl.STORE_URL + '/logout/',
                                 data={'sessionid': self._get_session_id()})
        if await self.is_session_alive():
            raise Exception("Logout unsuccessful")
        self.was_login_executed = False

    async def is_session_alive(self):
        response = await self._session.get(SteamUrl.COMMUNITY_URL)
        response = await response.text()
        return '>%s<' % self.username.lower() in response.lower()

    async def api_call(self,
                       url: URL,
                       params: dict = None,
                       post: bool = False) -> dict:
        if post:
            response = await self._api_session.post(url, data=params)
        else:
            response = await self._api_session.get(url, params=params)

        if response.status == 200:
            return await response.json()

        response_text = await response.text()
        if response.status == 403 and self._is_invalid_api_key(response_text):
            raise InvalidCredentials('Invalid API key')
        else:
            raise Exception(response_text)

    @staticmethod
    def _is_invalid_api_key(response: str) -> bool:
        msg = """Access is denied. Retrying will not help.
                 Please verify your <pre>key=</pre> parameter"""
        return msg in response

    @login_required
    def get_my_inventory(self,
                         game: GameOptions,
                         merge: bool = True,
                         count: int = 5000) -> dict:
        return self.get_partner_inventory(self.steam_id, game, merge, count)

    @login_required
    def get_partner_inventory(self,
                              partner_steam_id: str,
                              game: GameOptions,
                              merge: bool = True,
                              count: int = 5000) -> dict:
        url = '/'.join([SteamUrl.COMMUNITY_URL, 'inventory',
                        partner_steam_id, game.app_id, game.context_id])
        params = {'l': 'english', 'count': count}
        response_dict = self._session.get(url, params=params).json()

        if response_dict['success'] != 1:
            raise ApiException('Success value should be 1.')
        if merge:
            return merge_items_with_descriptions_from_inventory(response_dict,
                                                                game)
        return response_dict

    def _get_session_id(self) -> str:
        return self._session.cookie_jar.filter_cookies(
            URL(SteamUrl.HELP_URL)
        ).get('sessionid').value

    def get_trade_offers_summary(self) -> dict:
        params = {'key': self._api_key}
        return self.api_call('GET', 'IEconService',
                             'GetTradeOffersSummary', 'v1', params).json()

    def get_trade_offers(self, merge: bool = True) -> dict:
        params = {
            'key': self._api_key,
            'get_sent_offers': 1,
            'get_received_offers': 1,
            'get_descriptions': 1,
            'language': 'english',
            'active_only': 1,
            'historical_only': 0,
            'time_historical_cutoff': ''
        }
        response = self.api_call('GET', 'IEconService',
                                 'GetTradeOffers', 'v1', params).json()
        response = self._filter_non_active_offers(response)
        if merge:
            response = merge_items_with_descriptions_from_offers(response)
        return response

    @staticmethod
    def _filter_non_active_offers(offers_response):
        offers_received = offers_response['response'].get('trade_offers_received', [])
        offers_sent = offers_response['response'].get('trade_offers_sent', [])
        offers_response['response']['trade_offers_received'] = list(
            filter(lambda offer: offer['trade_offer_state'] == TradeOfferState.Active, offers_received))
        offers_response['response']['trade_offers_sent'] = list(
            filter(lambda offer: offer['trade_offer_state'] == TradeOfferState.Active, offers_sent))
        return offers_response

    def get_trade_offer(self, trade_offer_id: str, merge: bool = True) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id,
                  'language': 'english'}
        response = self.api_call('GET', 'IEconService', 'GetTradeOffer', 'v1', params).json()
        if merge and "descriptions" in response['response']:
            descriptions = {get_description_key(offer): offer for offer in response['response']['descriptions']}
            offer = response['response']['offer']
            response['response']['offer'] = merge_items_with_descriptions_from_offer(offer, descriptions)
        return response

    def get_trade_history(self,
                          max_trades=100,
                          start_after_time=None,
                          start_after_tradeid=None,
                          get_descriptions=True,
                          navigating_back=True,
                          include_failed=True,
                          include_total=True) -> dict:
        params = {
            'key': self._api_key,
            'max_trades': max_trades,
            'start_after_time': start_after_time,
            'start_after_tradeid': start_after_tradeid,
            'get_descriptions': get_descriptions,
            'navigating_back': navigating_back,
            'include_failed': include_failed,
            'include_total': include_total
        }
        response = self.api_call('GET', 'IEconService',
                                 'GetTradeHistory', 'v1', params).json()
        return response

    @login_required
    def get_trade_receipt(self, trade_id: str) -> list:
        html = self._session.get(
            "https://steamcommunity.com/trade/{}/receipt".format(trade_id)
        ).content.decode()
        items = []
        for item in texts_between(html, "oItem = ", ";\r\n\toItem"):
            items.append(json.loads(item))
        return items

    @login_required
    def accept_trade_offer(self, trade_offer_id: str) -> dict:
        trade = self.get_trade_offer(trade_offer_id)
        trade_offer_state = TradeOfferState(trade['response']['offer']['trade_offer_state'])
        if trade_offer_state is not TradeOfferState.Active:
            raise ApiException("Invalid trade offer state: {} ({})".format(trade_offer_state.name,
                                                                           trade_offer_state.value))
        partner = self._fetch_trade_partner_id(trade_offer_id)
        session_id = self._get_session_id()
        accept_url = SteamUrl.COMMUNITY_URL + '/tradeoffer/' + trade_offer_id + '/accept'
        params = {
            'sessionid': session_id,
            'tradeofferid': trade_offer_id,
            'serverid': '1',
            'partner': partner,
            'captcha': ''
        }
        headers = {'Referer': self._get_trade_offer_url(trade_offer_id)}
        response = self._session.post(accept_url, data=params, headers=headers).json()
        if response.get('needs_mobile_confirmation', False):
            return self._confirm_transaction(trade_offer_id)
        return response

    def _fetch_trade_partner_id(self, trade_offer_id: str) -> str:
        url = self._get_trade_offer_url(trade_offer_id)
        offer_response_text = self._session.get(url).text
        if 'You have logged in from a new device. In order to protect the items' in offer_response_text:
            raise SevenDaysHoldException("Account has logged in a new device and can't trade for 7 days")
        return text_between(offer_response_text, "var g_ulTradePartnerSteamID = '", "';")

    def _confirm_transaction(self, trade_offer_id: str) -> dict:
        confirmation_executor = ConfirmationExecutor(
            self._identity_secret, self.steam_id, self._session
        )
        return confirmation_executor.send_trade_allow_request(trade_offer_id)

    def decline_trade_offer(self, trade_offer_id: str) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id}
        return self.api_call('POST', 'IEconService', 'DeclineTradeOffer', 'v1', params).json()

    def cancel_trade_offer(self, trade_offer_id: str) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id}
        return self.api_call('POST', 'IEconService', 'CancelTradeOffer', 'v1', params).json()

    @login_required
    def make_offer(self, items_from_me: List[Asset], items_from_them: List[Asset], partner_steam_id: str,
                   message: str = '') -> dict:
        offer = self._create_offer_dict(items_from_me, items_from_them)
        session_id = self._get_session_id()
        url = SteamUrl.COMMUNITY_URL + '/tradeoffer/new/send'
        server_id = 1
        params = {
            'sessionid': session_id,
            'serverid': server_id,
            'partner': partner_steam_id,
            'tradeoffermessage': message,
            'json_tradeoffer': json.dumps(offer),
            'captcha': '',
            'trade_offer_create_params': '{}'
        }
        partner_account_id = steam_id_to_account_id(partner_steam_id)
        headers = {'Referer': SteamUrl.COMMUNITY_URL + '/tradeoffer/new/?partner=' + partner_account_id,
                   'Origin': SteamUrl.COMMUNITY_URL}
        response = self._session.post(url, data=params, headers=headers).json()
        if response.get('needs_mobile_confirmation'):
            response.update(self._confirm_transaction(response['tradeofferid']))
        return response

    async def get_profile(self, steam_id: str) -> dict:
        """
        https://developer.valvesoftware.com/wiki/Steam_Web_API#GetPlayerSummaries_.28v0002.29
        """
        response = await self.api_call(
            SteamUrl.API / 'ISteamUser/GetPlayerSummaries/v0002',
            {'steamids': steam_id, 'key': self._api_key}
        )
        return response['response']['players'][0]

    def get_friend_list(self, steam_id: str, relationship_filter: str="all") -> dict:
        params = {
            'key': self._api_key,
            'steamid': steam_id,
            'relationship': relationship_filter
        }
        resp = self.api_call("GET", "ISteamUser", "GetFriendList", "v1", params)
        data = resp.json()
        return data['friendslist']['friends']

    @staticmethod
    def _create_offer_dict(items_from_me: List[Asset], items_from_them: List[Asset]) -> dict:
        return {
            'newversion': True,
            'version': 4,
            'me': {
                'assets': [asset.to_dict() for asset in items_from_me],
                'currency': [],
                'ready': False
            },
            'them': {
                'assets': [asset.to_dict() for asset in items_from_them],
                'currency': [],
                'ready': False
            }
        }

    @login_required
    def get_escrow_duration(self, trade_offer_url: str) -> int:
        headers = {'Referer': SteamUrl.COMMUNITY_URL + urlparse.urlparse(trade_offer_url).path,
                   'Origin': SteamUrl.COMMUNITY_URL}
        response = self._session.get(trade_offer_url, headers=headers).text
        my_escrow_duration = int(text_between(response, "var g_daysMyEscrow = ", ";"))
        their_escrow_duration = int(text_between(response, "var g_daysTheirEscrow = ", ";"))
        return max(my_escrow_duration, their_escrow_duration)

    @login_required
    def make_offer_with_url(self, items_from_me: List[Asset], items_from_them: List[Asset],
                            trade_offer_url: str, message: str = '', case_sensitive: bool=True) -> dict:
        token = get_key_value_from_url(trade_offer_url, 'token', case_sensitive)
        partner_account_id = get_key_value_from_url(trade_offer_url, 'partner', case_sensitive)
        partner_steam_id = account_id_to_steam_id(partner_account_id)
        offer = self._create_offer_dict(items_from_me, items_from_them)
        session_id = self._get_session_id()
        url = SteamUrl.COMMUNITY_URL + '/tradeoffer/new/send'
        server_id = 1
        trade_offer_create_params = {'trade_offer_access_token': token}
        params = {
            'sessionid': session_id,
            'serverid': server_id,
            'partner': partner_steam_id,
            'tradeoffermessage': message,
            'json_tradeoffer': json.dumps(offer),
            'captcha': '',
            'trade_offer_create_params': json.dumps(trade_offer_create_params)
        }
        headers = {'Referer': SteamUrl.COMMUNITY_URL + urlparse.urlparse(trade_offer_url).path,
                   'Origin': SteamUrl.COMMUNITY_URL}
        response = self._session.post(url, data=params, headers=headers).json()
        if response.get('needs_mobile_confirmation'):
            response.update(self._confirm_transaction(response['tradeofferid']))
        return response

    @staticmethod
    def _get_trade_offer_url(trade_offer_id: str) -> str:
        return SteamUrl.COMMUNITY_URL + '/tradeoffer/' + trade_offer_id

    @login_required
    def get_wallet_balance(self, convert_to_float: bool = True) -> Union[str, float]:
        url = SteamUrl.STORE_URL + '/account/history/'
        response = self._session.get(url)
        response_soup = bs4.BeautifulSoup(response.text, "html.parser")
        balance = response_soup.find(id='header_wallet_balance').string
        if convert_to_float:
            return price_to_float(balance)
        else:
            return balance

    def set_session_file(self) -> None:
        try:
            if self.session_file:
                if self.session_file.is_dir():
                    raise InvalidSessionPath('session_file should not point to a directory')
            elif self.sessions_dir:
                if self.sessions_dir.is_file():
                    raise InvalidSessionPath('sessions_dir should not point to a file')
                if not self.steam_id:
                    raise InvalidSessionPath(
                        "steam_id is required to save or load sessions from a directory"
                    )
                self.session_file = self.sessions_dir / self.steam_id
            else:
                raise Exception('No session_file or sessions_dir was provided')
        except InvalidSessionPath as err:
            # prevent saving session to invalid file
            self.reuse_session = False
            raise err
