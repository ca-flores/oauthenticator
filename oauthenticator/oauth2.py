"""
Base classes for Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import os
import subprocess

from tornado import gen, web

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from tornado.httpclient import AsyncHTTPClient

from traitlets import Unicode


class OAuthLoginHandler(BaseHandler):
    """Base class for OAuth login handler

    Typically subclasses will need
    """
    scope = []

    def get(self):
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )

        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('oauth redirect: %r', redirect_uri)

        self.set_oauth_urls(
            oauth_authorize_url=self.authenticator.oauth_authorize_url,
            oauth_access_token_url=self.authenticator.oauth_access_token_url)

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.scope,
            response_type='code')

class OAuthLogoutHandler(BaseHandler):
    pass

class OAuthCallbackHandler(BaseHandler):
    """Basic handler for OAuth callback. Calls authenticator to verify username."""
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.get_authenticated_user(self, None)

        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class OAuthenticator(Authenticator):
    """Base class for OAuthenticators

    Subclasses must override:

    login_service (string identifying the service provider)
    login_handler (likely a subclass of OAuthLoginHandler)
    authenticate (method takes one arg - the request handler handling the oauth callback)
    """

    login_service = 'override in subclass'
    
    oauth_authorize_url = Unicode(config=True)
    oauth_access_token_url = Unicode(config=True)
    oauth_callback_url = Unicode(
        config=True,
        help="""Callback URL to use.
        Typically `https://{host}/hub/oauth_callback`"""
    )

    oauth_logout_url = Unicode(
        config=True,
        help="""Logout URL to use.
        Typically `https://{host}/hub/logout
        `"""
    )
    oauth_profile_url = Unicode(config=True)
    grant_type = Unicode(config=True)


    client_id_env = 'OAUTH_CLIENT_ID'
    client_id = Unicode(config=True)
    def _client_id_default(self):
        return os.getenv(self.client_id_env, '')

    client_secret_env = 'OAUTH_CLIENT_SECRET'
    client_secret = Unicode(config=True)
    def _client_secret_default(self):
        return os.getenv(self.client_secret_env, '')

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')

    def logout_url(self, base_url):
        return url_path_join(base_url, 'logout')

    login_handler = "Specify login handler class in subclass"
    logout_handler = "Specify logout handler class in subclass"
    callback_handler = OAuthCallbackHandler

    def get_handlers(self, app):
        return [
            (r'/oauth_login', self.login_handler),
            (r"/logout", self.logout_handler),
            (r'/oauth_callback', self.callback_handler),
        ]

    
    def parse_response(self, response):
        """ 
        Input: response of oauth service. It contains a valid token 
        Ouput: parsed response in json or any other valid format 
            for the current authenticator
        """
        raise NotImplementedError()

    @gen.coroutine
    def authenticate(self, handler, data=None):
        raise NotImplementedError()
