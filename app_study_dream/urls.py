from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path, re_path
from .views import *
from app_study_dream import views
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.auth import views as auth_views
# hihi
urlpatterns = [
    path('list_page/', views.list_page, name='list_page'), # 로그인 성공 시, settings.py 에서 지정한 LOGIN_REDIRECT_URL 인 list_page/ 로 이동시 나오는 url 설정
    path('', views.list_page, name='list_page'), # 로그인 성공 시, settings.py 에서 지정한 LOGIN_REDIRECT_URL 인 list_page/ 로 이동시 나오는 url 설정
    path('post/<int:id>', views.detail, name='detail'),
    path('write_post', views.write_post, name='write_post'),
    re_path(r'^write_post/$', write_post, name='write_post'),
    path('login/', login_view2, name='login'), # LoginView : 장고에서 사용되는 클래스 기반 뷰(폼 입력 처리로 로그인 수행)
    path('logout', LogoutView.as_view(), name='logout'),
    path('post/delete/<int:board_id>', delete_board, name='delete_board'),
    path('search/', search, name='search'),
    path('signup', views.signup, name='signup'),
    path('edit/<int:id>/', boardEdit, name='edit'),
    path('ping_counter', ping_counter, name='ping_counter'),
    path('comment/', comment_view, name='comment_view'),
    path('add_comment/', add_comment, name='add_comment'),
    ]