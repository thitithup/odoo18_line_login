# -*- coding: utf-8 -*-
# See LICENSE file for full copyright and licensing details.

{
    'name': 'OAuth2 Authentication with Line Login',
    'category': 'Tools',
    'description': """
Allow users to login through Line Login Provider.
=============================================
""",
    'author': 'INECO LTD.,PART.',
    'depends': ['base', 'auth_oauth', 'auth_signup'],
    'data': [
        'views/auth_oauth_views.xml',
        'data/auth_oauth_data.xml',
    ],
    'demo': [],
    'installable': True,
    'auto_install': False,
    'application': True,
    'images': [],
}
