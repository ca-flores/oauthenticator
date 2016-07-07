"""
Custom Authenticator to set an own Single Sign On server with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os
import sys

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
    _OAUTH_AUTHORIZE_URL = AUX_OAUTH_AUTHORIZE_URL
    _OAUTH_ACCESS_TOKEN_URL = AUX_OAUTH_ACCESS_TOKEN_URL

class SingleSignOnLoginHandler(OAuthLoginHandler, SingleSignOnMixin):
    pass

class SingleSignOnLogoutHandler(BaseHandler):
    """Class for OAuth logout handler"""

    @gen.coroutine
    def get(self):
        http_client = AsyncHTTPClient()
        user = self.get_current_user()
        if user:
            self.log.info("User logged out: %s", user.name)
            self.clear_login_cookie()
            for name in user.other_user_cookies:
                self.clear_login_cookie(name)
            user.other_user_cookies = set([])
        # Stratio Intelligence Modification
        # Stop_single_user added in Sprint 7 in order to stop container in logout
        self.stop_single_user(user)
        self.redirect(AUX_OAUTH_LOGOUT_URL, permanent=False)


class SingleSignOnOAuthenticator(OAuthenticator):
    """
    Custom Authenticator for custom OAuth server
    """
    login_service = "SingleSignOn"
    client_secret_env = 'SINGLESIGNON_CLIENT_SECRET'
    login_handler = SingleSignOnLoginHandler
    logout_handler = SingleSignOnLogoutHandler
    @gen.coroutine
    def authenticate(self, handler, data=None):
        self.log.info("SingleSignOnOAuthenticator...authenticate...")
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")

        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a Custom OAuth Access Token
        # API specifies a GET request yet requires URL parameters
        token_req_param = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type=self.grant_type,
            redirect_uri=self.oauth_callback_url,
            code=code
        )

        if not AUX_OAUTH_ACCESS_TOKEN_URL:
            raise web.HTTPError(400, "OAUTH_ACCESS_TOKEN_URL is not defined")

        token_url = url_concat(AUX_OAUTH_ACCESS_TOKEN_URL, token_req_param)
        token_req = HTTPRequest(url=token_url,
                          method="GET",
                          headers={"Accept": "application/json"}
                          )

        resp = yield http_client.fetch(token_req)
        # Parse fetch response, in this case fetch returns a string
        # that is processed to convert it to JSON string format
        # We retrieve a valid token and an extra param that is called "expired"
        body_str = resp.body.decode('utf8', 'replace')
        body_str = body_str.replace("=", "\":\"")
        body_str = body_str.replace("&", "\",\"")
        json_str = "{\""+body_str+"\"}"
        self.log.debug("Response valid token: %s" % json_str)
        # Parse json_str to json object
        resp_json = json.loads(json_str)

        profile_req_params = dict(
            access_token=resp_json['access_token']
        )
        # Retrieve user information with a valid token obtained from the previous
        # request
        if not AUX_OAUTH_PROFILE_URL:
            raise web.HTTPError(400, "OAUTH_PROFILE_URL is not defined")
        profile_url = url_concat(AUX_OAUTH_PROFILE_URL, profile_req_params)
        profile_req = HTTPRequest(profile_url)
        resp = yield http_client.fetch(profile_req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        # This request returns a JSON string
        self.log.info("OAuth user id: %s" % resp_json['id'])
        # User id is returned to be registered into app data base
        return resp_json['id']


class LocalSingleSignOnOAuthenticator(LocalAuthenticator, SingleSignOnOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
