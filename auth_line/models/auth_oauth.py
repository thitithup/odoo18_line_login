# -*- coding: utf-8 -*-
# See LICENSE file for full copyright and licensing details.

from odoo import fields, models


class AuthOAuthProvider(models.Model):
    _inherit = 'auth.oauth.provider'

    is_line_oauth = fields.Boolean(string='Line Login')
    line_token_endpoint = fields.Char(string='Token URL')
    line_secret = fields.Char(string='Client Secret')
    line_callback_uri = fields.Char(string='Line Callback Uri')
