from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path
from .views import *
from app_study_dream import views
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.auth import views as auth_views
# hoho
urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='login.html'), name='login'), # LoginView 함수가 authenticate, login 함수 사용한다.
    path('list_page/', views.list_page, name='list_page'), # 로그인 성공 시, settings.py 에서 지정한 LOGIN_REDIRECT_URL 인 list_page/ 로 이동시 나오는 url 설정
    path('post/<int:id>', views.detail, name='detail'),
    path('write_post', views.write_post, name='write_post'),
    path('login_2', login_view2, name='login_2'), # LoginView : 장고에서 사용되는 클래스 기반 뷰(폼 입력 처리로 로그인 수행)
    path('login_3/', login_view3, name='login_3'), # LoginView : 장고에서 사용되는 클래스 기반 뷰(폼 입력 처리로 로그인 수행)
    path('logout', LogoutView.as_view(), name='logout'),
    path('success/', success_view),
    path('error/', error_view),
    path('home_page', home_page),
    path('post/delete/<int:board_id>', delete_board, name='delete_board'),
    path('search/', search, name='search'),
    path('signup', views.signup, name='signup'),
    path('edit/<int:id>/', boardEdit, name='edit'),
    ]
