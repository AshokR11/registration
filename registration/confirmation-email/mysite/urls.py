from django.conf.urls import url, include
from django.contrib.auth import views as auth_views

from mysite.core import views as core_views


urlpatterns = [
    url(r'^$', core_views.home, name='home'),
    url(r'^login/$', auth_views.login, {'template_name': 'login.html'}, name='login'),
    url(r'^logout/$', auth_views.logout, {'next_page': 'login'}, name='logout'),
    url(r'accounts/lost-password/', core_views.forgetpassword, name='forgetpassword'),
    url(r'^signup/$', core_views.signup, name='signup'),
    url(r'^account_activation_sent/$', core_views.account_activation_sent, name='account_activation_sent'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        core_views.activate, name='activate'),
    url('^', include('django.contrib.auth.urls')),
    url(r'^reset-password/$', auth_views.password_reset, {'template_name': 'accounts/reset_password.html', 'post_reset_redirect': 'accounts:password_reset_done', 'email_template_name': 'accounts/reset_password_email.html'}, name='reset_password'),

    url(r'^reset-password/done/$', auth_views.password_reset_done, {'template_name': 'accounts/reset_password_done.html'}, name='password_reset_done'),

    url(r'^reset-password/confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', auth_views.password_reset_confirm, {'template_name': 'accounts/reset_password_confirm.html', 'post_reset_redirect': 'accounts:password_reset_complete'}, name='password_reset_confirm'),

    url(r'^reset-password/complete/$', auth_views.password_reset_complete,{'template_name': 'accounts/reset_password_complete.html'}, name='password_reset_complete'),
    url(r'accounts/verify/(?P<emailaddr>\w+)', core_views.reset_pass_red_view, name='reset_pass_red_view'),
    url(r'accounts/reset-password/', core_views.reset_password_view, name='reset_password_view'),
]
