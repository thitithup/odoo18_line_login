# -*- coding: utf-8 -*-
# See LICENSE file for full copyright and licensing details.

from odoo.addons.auth_oauth.controllers.main import OAuthLogin, OAuthController, fragment_to_query_string
from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.exceptions import UserError
from odoo.addons.auth_signup.models.res_users import SignupError
import logging
from odoo.http import request, Controller
import json
import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest
from odoo import api, http, SUPERUSER_ID, _
from odoo.addons.web.controllers.utils import ensure_db, _get_login_redirect_url
from odoo.tools.misc import clean_context
# from odoo.addons.web.controllers.main import ensure_db, set_cookie_and_redirect, login_and_redirect
from odoo import registry as registry_get
from odoo.exceptions import AccessDenied
import requests
import jwt
import os
import base64

_logger = logging.getLogger(__name__)


class AuthSignupHome(AuthSignupHome):
    @http.route('/web/signup', type='http', auth='public', website=True, sitemap=False)
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            try:
                self.do_signup(qcontext)

                if qcontext.get('token'):
                    user_sudo = request.env['res.users'].sudo().search([('login', '=', qcontext.get('login'))])
                    template = request.env.ref('auth_signup.mail_template_user_signup_account_created',
                                               raise_if_not_found=False)
                    if user_sudo and template:
                        template.sudo().with_context(
                            lang=user_sudo.lang,
                            auth_login=werkzeug.url_encode({'auth_login': user_sudo.email}),
                        ).send_mail(user_sudo.id, force_send=True)
                else:

                    request.session.logout()
                    user_sudo = request.env['res.users'].sudo().search([('login', '=', qcontext.get('login'))])
                    template = request.env.ref('auth_line.mail_template_user_signup_account_activate',
                                               raise_if_not_found=False)
                    if user_sudo and template:
                        template.sudo().with_context(
                            lang=user_sudo.lang,
                            auth_login=werkzeug.url_encode({'auth_login': user_sudo.email}),
                        ).send_mail(user_sudo.id, force_send=True)
                        user_sudo.set_inactivate()
                    return werkzeug.utils.redirect('/web/login', 303)
                return self.web_login(*args, **kw)
            except UserError as e:
                qcontext['error'] = e.name or e.value
            except (SignupError, AssertionError) as e:
                if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
                    qcontext["error"] = _("Another user is already registered using this email address.")
                else:
                    _logger.error("%s", e)
                    qcontext['error'] = _("Could not create a new account.")

        response = request.render('auth_signup.signup', qcontext)
        response.headers['X-Frame-Options'] = 'DENY'
        return response


class OAuthLogin(OAuthLogin):
    def list_providers(self):
        try:
            providers = request.env['auth.oauth.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            providers = []
        for provider in providers:
            return_url = request.httprequest.url_root + 'auth_oauth/signin'
            state = self.get_state(provider)
            if provider['is_line_oauth'] == True:
                return_url = return_url.replace('http:', 'https:')
                params = dict(
                    response_type='code',
                    client_id=provider['client_id'],
                    redirect_uri=return_url,
                    scope=provider['scope'],
                    state=json.dumps(state),
                )
            else:
                params = dict(
                    response_type='token',
                    client_id=provider['client_id'],
                    redirect_uri=return_url,
                    scope=provider['scope'],
                    state=json.dumps(state),
                    nonce=base64.urlsafe_b64encode(os.urandom(16)),
                    # nonce=base64.urlsafe_b64encode(os.urandom(16)),
                )
            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        return providers


class OAuthController(OAuthController):
    @http.route('/auth_oauth/signin', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        state = json.loads(kw['state'])
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()
        provider = state['p']
        ensure_db(db=dbname)
        request.update_context(**clean_context(state.get('c', {})))

        provider_obj = request.env['auth.oauth.provider'].sudo().browse(provider)
        if provider_obj.is_line_oauth == True:
            header = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            body = {
                'grant_type': 'authorization_code',
                'code': kw['code'],
                'redirect_uri': provider_obj.line_callback_uri,
                'client_id': provider_obj.client_id,
                'client_secret': provider_obj.line_secret
            }
            r = requests.post(url='https://api.line.me/oauth2/v2.1/token',
                              headers=header,
                              data=body)
            result = r.json()
            kw['id_token'] = result['id_token']
            kw['access_token'] = result['access_token']

        try:

            _, login, key = request.env['res.users'].with_user(SUPERUSER_ID).auth_oauth(provider, kw)
            request.env.cr.commit()

            action = state.get('a')
            menu = state.get('m')
            redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
            url = '/odoo'
            if redirect:
                url = redirect
            elif action:
                url = '/odoo/action-%s' % action
            elif menu:
                url = '/odoo?menu_id=%s' % menu

            credential = {'login': login, 'password': key, 'type': 'password'}
            auth_info = request.session.authenticate(dbname, credential)
            resp = request.redirect(_get_login_redirect_url(auth_info['uid'], url), 303)
            resp.autocorrect_location_header = False

            if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user._is_internal():
                resp.location = '/'
            return resp
        except AttributeError:  # TODO juc master: useless since ensure_db()
            # auth_signup is not installed
            _logger.error("auth_signup not installed on database %s: oauth sign up cancelled.", dbname)
            url = "/web/login?oauth_error=1"
        except AccessDenied:
            # oauth credentials not valid, user could be on a temporary session
            _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
            url = "/web/login?oauth_error=3"
        except Exception:
            # signup error
            _logger.exception("Exception during request handling")
            url = "/web/login?oauth_error=2"

        redirect = request.redirect(url, 303)
        redirect.autocorrect_location_header = False
        return redirect



class LineController(Controller):
    @http.route(['/web/activate'], auth='public')
    def active_new_user(self, **kwargs):
        if 'auth_login' in kwargs:
            user = request.env['res.users'].sudo().search([('login', '=', kwargs['auth_login'])])
            user.write({'activate': True})
        return werkzeug.utils.redirect('/web/login', 303)
