# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import fields, models, api, tools, SUPERUSER_ID
from odoo.exceptions import AccessDenied, UserError
import logging
import jwt
import json

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        new_params = params.copy()
        if oauth_provider.is_line_oauth:
            access_token = new_params.get('id_token')
            state = json.loads(params['state'])
            # state['t'] = new_params.get('access_token')
            new_params['state'] = json.dumps(state)
        else:
            access_token = new_params.get('access_token')
        validation = self._auth_oauth_validate(provider, access_token)

        login = self._auth_oauth_signin(provider, validation, new_params)
        if not login:
            raise AccessDenied()

        return (self.env.cr.dbname, login, access_token)

    @api.model
    def _auth_oauth_validate(self, provider, access_token):
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        if oauth_provider.is_line_oauth:
            id_token = access_token
            validation = jwt.decode(id_token,
                                    oauth_provider.line_secret,
                                    audience=oauth_provider.client_id,
                                    issuer='https://access.line.me',
                                    algorithms=['HS256'])
            validation_sample = {'iss': 'https://access.line.me', 'sub': 'Uac6aa4ae3c162aa89d3c44f8b7d1c4d3',
                                 'aud': '1654663761',
                                 'exp': 1727858579, 'iat': 1727854979, 'amr': ['linesso'], 'name': 'ธิติทัพพ์ ศรีสุขโข',
                                 'picture': 'https://profile.line-scdn.net/0hU065JfVvCh8LTCEpZj11SDcJBHJ8YgxXc34Sfy5NASZ2eEhMYywSKi5JVSpxehhJPyJMcShLUSkh',
                                 'email': 'k.pop@ineco.co.th'}
        else:
            validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token)
            if validation.get("error"):
                raise Exception(validation['error'])
            if oauth_provider.data_endpoint:
                data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
                validation.update(data)

        subject = next(filter(None, [
            validation.pop(key, None)
            for key in [
                'sub',  # standard
                'id',  # google v1 userinfo, facebook opengraph
                'user_id',  # google tokeninfo, odoo (tokeninfo)
            ]
        ]), None)
        if not subject:
            raise AccessDenied('Missing subject identity')
        validation['user_id'] = subject
        return validation

    def _check_credentials(self, credential, env):
        try:
            return super()._check_credentials(credential, env)
        except AccessDenied:
            passwd_allowed = env['interactive'] or not self.env.user._rpc_api_keys_only()
            if passwd_allowed and self.env.user.active:
                if self.env.user.oauth_provider_id.is_line_oauth:
                    res = self.sudo().search([('id', '=', self.env.uid)])
                else:
                    res = self.sudo().search([('id', '=', self.env.uid), ('oauth_access_token', '=', credential['password'])])
                if res:
                    return {
                        'uid': self.env.user.id,
                        'auth_method': 'oauth',
                        'mfa': 'default',
                    }
            raise
