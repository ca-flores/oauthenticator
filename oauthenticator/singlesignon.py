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

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Connection to Sigle Sign On server
"""
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com/user'
else:
    GITHUB_API = '%s/api/v3/user' % GITHUB_HOST
"""

class SingleSignOnMixin(OAuth2Mixin):
    # self.log.warn("...SingleSignOnMixin...")
    _OAUTH_AUTHORIZE_URL = os.getenv('OAUTH_AUTHORIZE_URL', '')
    # if not _OAUTH_AUTHORIZE_URL:
        # self.log.error("OAUTH_AUTHORIZE_URL should be set before to continue")
        # raise HTTPError(400, "OAUTH_AUTHORIZE_URL has not been set. Check your server configuration")
    _OAUTH_ACCESS_TOKEN_URL = os.getenv('OAUTH_ACCESS_TOKEN_URL', '')
    # if not _OAUTH_ACCESS_TOKEN_URL:
        # self.log.error("OAUTH_ACCESS_TOKEN_URL should be set before to continue")
        # raise HTTPError(400, "OAUTH_ACCESS_TOKEN_URL has not been set. Check your server configuration")
    # self.log.warn("---SingleSignOnMixin---")

class SingleSignOnLoginHandler(OAuthLoginHandler, SingleSignOnMixin):
    pass

class SingleSignOnOAuthenticator(OAuthenticator):
    # self.log.warn("...SingleSignOnOAuthenticator...")
    login_service = "SingleSignOn"
    """
    # deprecated names
    github_client_id = Unicode(config=True, help="DEPRECATED")
    def _github_client_id_changed(self, name, old, new):
        self.log.warn("github_client_id is deprecated, use client_id")
        self.client_id = new
    github_client_secret = Unicode(config=True, help="DEPRECATED")
    def _github_client_secret_changed(self, name, old, new):
        self.log.warn("github_client_secret is deprecated, use client_secret")
        self.client_secret = new
    """

    client_id_env = 'SINGLESIGNON_CLIENT_ID'
    client_secret_env = 'SINGLESIGNON_CLIENT_SECRET'
    login_handler = SingleSignOnLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        self.log.warn("...authenticate...")
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )
        """
        url = url_concat("https://%s/login/oauth/access_token" % GITHUB_HOST,
                         params)
        """

        OAUTH_AUTHORIZE_URL = os.getenv('OAUTH_AUTHORIZE_URL', '')
        if not OAUTH_AUTHORIZE_URL:
            self.log.error("OAUTH_AUTHORIZE_URL should be set before to continue")
            raise HTTPError(400, "OAUTH_AUTHORIZE_URL has not been set. Check your server configuration")
        OAUTH_ACCESS_TOKEN_URL = os.getenv('OAUTH_ACCESS_TOKEN_URL', '')
        if not OAUTH_ACCESS_TOKEN_URL:
            self.log.error("OAUTH_ACCESS_TOKEN_URL should be set before to continue")
            raise HTTPError(400, "OAUTH_ACCESS_TOKEN_URL has not been set. Check your server configuration")

        url = OAUTH_ACCESS_TOKEN_URL
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['details']['tokenValue']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "token {}".format(access_token)
        }
        req = HTTPRequest("https://%s" % GITHUB_API,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        # TODO Retrieve userprofile that should return user's attributes
        self.log.warn("---authenticate---")

        return resp_json["userAuthentication"]["details"]["id"]

    # self.log.warn("---SingleSignOnOAuthenticator---")


class LocalSingleSignOnOAuthenticator(LocalAuthenticator, SingleSignOnOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
