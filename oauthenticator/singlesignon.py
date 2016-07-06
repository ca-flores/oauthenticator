"""
Custom Authenticator to set an own Single Sign On server with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.utils import url_path_join
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers import BaseHandler

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Looking for urls that have been set as Environment Variables
AUX_OAUTH_AUTHORIZE_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/authorize"
AUX_OAUTH_ACCESS_TOKEN_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/accessToken"
AUX_OAUTH_PROFILE_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/profile"
AUX_OAUTH_LOGOUT_URL = "https://gosec.int.stratio.com/gosec-sso/logout"


class SingleSignOnMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = os.getenv('OAUTH_AUTHORIZE_URL', AUX_OAUTH_AUTHORIZE_URL)
    _OAUTH_ACCESS_TOKEN_URL = os.getenv('OAUTH_ACCESS_TOKEN_URL', AUX_OAUTH_ACCESS_TOKEN_URL)

class SingleSignOnLoginHandler(OAuthLoginHandler, SingleSignOnMixin):
    pass

class SingleSignOnLogoutHandler(BaseHandler, OAuthenticator):
    """Class for OAuth logout handler"""

    @gen.coroutine
    def get(self):
        http_client = AsyncHTTPClient()
        req =  HTTPRequest(url=self.oauth_logout_url,
                          method="GET",
                          headers={"Accept": "application/json"}
                          )
        resp = yield http_client.fetch(req)
        decoded = resp.body.decode()
        user = self.get_current_user()
        if user:
            self.log.info("User logged out: %s", user.name)
            self.clear_login_cookie()
            for name in user.other_user_cookies:
                self.clear_login_cookie(name)
            user.other_user_cookies = set([])
        self.redirect(self.hub.server.base_url, permanent=False)


class SingleSignOnOAuthenticator(OAuthenticator):
    """
    Custom Authenticator for custom OAuth server
    """
    login_service = "SingleSignOn"
    client_secret_env = 'SINGLESIGNON_CLIENT_SECRET'
    login_handler = SingleSignOnLoginHandler
    logout_handler = SingleSignOnLogoutHandler
    oauth_logout_url = Unicode(
        os.getenv('OAUTH_LOGOUT_URL', AUX_OAUTH_LOGOUT_URL),
        config=True,
        help="""Logout URL to use.
        Typically `https://{host}/hub/logout
        `"""
    )
    grant_type = Unicode(config=True)
    @gen.coroutine
    def authenticate(self, handler, data=None):
        self.log.info("SingleSignOnOAuthenticator...authenticate...")
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a Custom OAuth Access Token
        # API specifies a GET request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type=self.grant_type,
            redirect_uri=self.oauth_callback_url,
            code=code
        )

        url = os.getenv('OAUTH_ACCESS_TOKEN_URL', '')
        if not url:
            raise web.HTTPError(400, "OAUTH_ACCESS_TOKEN_URL is not defined")

        url = url_concat(url, params)
        req = HTTPRequest(url=url,
                          method="GET",
                          headers={"Accept": "application/json"}
                          )

        resp = yield http_client.fetch(req)
        # Parse fetch response, in this case fetch returns a string
        # that is processed to convert it to JSON string format
        # We retrieve a valid token and an extra param that is expired
        body_str = resp.body.decode('utf8', 'replace')
        body_str = body.replace("=", "\":\"")
        body_str = body.replace("&", "\",\"")
        json_str = "{\""+body+"\"}"
        self.log.debug("Response valid token: %s" % json_str)
        # Parse json_str to json object
        resp_json = json.loads(json_str)

        params = yield dict(
            access_token=resp_json['access_token']
        )
        # Retrieve user information with a valid token obtained from the previous
        # request
        url_profile = url_concat(AUX_OAUTH_PROFILE_URL, params)
        req = HTTPRequest(aux_url)
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        # This request returns a JSON string
        self.log.info("OAuth user id: %s" % resp_json['id'])
        # User id is returned to be registered into app data base
        return resp_json['id']


class LocalSingleSignOnOAuthenticator(LocalAuthenticator, SingleSignOnOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
