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

AUX_OAUTH_AUTHORIZE_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/authorize"
# AUX_OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
AUX_OAUTH_ACCESS_TOKEN_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/accessToken"
# AUX_OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST


class SingleSignOnMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = os.getenv('OAUTH_AUTHORIZE_URL', AUX_OAUTH_AUTHORIZE_URL)
    _OAUTH_ACCESS_TOKEN_URL = os.getenv('OAUTH_ACCESS_TOKEN_URL', AUX_OAUTH_ACCESS_TOKEN_URL)

class SingleSignOnLoginHandler(OAuthLoginHandler, SingleSignOnMixin):
    pass

class SingleSignOnLogoutHandler(BaseHandler):
    """Class for OAuth logout handler"""
    oauth_logout_url = Unicode(
        os.getenv('OAUTH_LOGOUT_URL', 'https://gosec.int.stratio.com/gosec-sso/logout'),
        config=True,
        help="""Logout URL to use.
        Typically `https://{host}/hub/logout
        `"""
    )
    @gen.coroutine
    def get(self):
        self.log.info("SingleSignOnLogoutHandler----")

        self.log.debug("oauth_logout to be called----")
        http_client = AsyncHTTPClient()
        req =  HTTPRequest(url='https://gosec.int.stratio.com/gosec-sso/logout',
                          method="GET",
                          headers={"Accept": "application/json"}
                          )
        resp = yield http_client.fetch(req)
        decoded = resp.body.decode()
        # self.log.info(decoded)
        user = self.get_current_user()
        if user:
            self.log.info("User logged out: %s", user.name)
            self.clear_login_cookie()
            for name in user.other_user_cookies:
                self.clear_login_cookie(name)
            user.other_user_cookies = set([])
            # self.statsd.incr('logout')
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
        os.getenv('OAUTH_LOGOUT_URL', 'https://gosec.int.stratio.com/gosec-sso/logout'),
        config=True,
        help="""Logout URL to use.
        Typically `https://{host}/hub/logout
        `"""
    )
    grant_type = Unicode(config=True)
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

        # aux_grant_type = "authorization_code"
        # "https://intelligence-dev:8000/hub/oauth_callback",
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type=self.grant_type,
            redirect_uri=self.oauth_callback_url,
            code=code
        )


        url = os.getenv('OAUTH_ACCESS_TOKEN_URL', AUX_OAUTH_ACCESS_TOKEN_URL) # _OAUTH_ACCESS_TOKEN_URL
        self.log.info('AUX_OAUTH_ACCESS_TOKEN_URL -- ' + url)

        ######
        url = url_concat(url, params)
        ######
        self.log.info('AUX_OAUTH_ACCESS_TOKEN_URL CONCATENATED -- ' + url)
        req = HTTPRequest(url=url,
                          method="GET",
                          headers={"Accept": "application/json"}
                          )

        resp = yield http_client.fetch(req)

        body = resp.body.decode('utf8', 'replace')
        body = body.replace("=", "\":\"")
        body = body.replace("&", "\",\"")
        json_str = "{\""+body+"\"}"
        print ("print json_str -> " + json_str)
        resp_json = json.loads(json_str)
        print (body)
        access_token = resp_json['access_token'] #resp_json['details']['tokenValue']
        aux_url = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/profile?access_token=%s" % access_token
        print (aux_url)
        req = HTTPRequest(aux_url)
        resp = yield http_client.fetch(req)
        # body_req2 = resp.body.decode('utf8', 'replace')
        resp_json2 = json.loads(resp.body.decode('utf8', 'replace'))
        # TODO Retrieve userprofile that should return user's attributes
        self.log.warn("---authenticate---: " + resp_json2['id'])
        # self.log.info(body_req2)

        return resp_json2['id']

    # self.log.warn("---SingleSignOnOAuthenticator---")


class LocalSingleSignOnOAuthenticator(LocalAuthenticator, SingleSignOnOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
