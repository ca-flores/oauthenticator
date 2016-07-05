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
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com/user'
else:
    GITHUB_API = '%s/api/v3/user' % GITHUB_HOST

AUX_OAUTH_AUTHORIZE_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/authorize"
# AUX_OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
AUX_OAUTH_ACCESS_TOKEN_URL = "https://gosec.int.stratio.com/gosec-sso/oauth2.0/accessToken"
# AUX_OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST


class SingleSignOnMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = os.getenv('OAUTH_AUTHORIZE_URL', AUX_OAUTH_AUTHORIZE_URL)
    _OAUTH_ACCESS_TOKEN_URL = os.getenv('OAUTH_ACCESS_TOKEN_URL', AUX_OAUTH_ACCESS_TOKEN_URL)

class SingleSignOnLoginHandler(OAuthLoginHandler, SingleSignOnMixin):
    pass

class SingleSignOnOAuthenticator(OAuthenticator):
    # self.log.warn("...SingleSignOnOAuthenticator...")
    login_service = "SingleSignOn"
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
        aux_grant_type = "authorization_code"
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type=aux_grant_type,
            redirect_uri="https://intelligence-dev:8000/hub/oauth_callback",
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
