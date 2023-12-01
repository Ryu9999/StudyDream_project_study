from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, Http404, HttpResponse, JsonResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from app_study_dream.models import Board
from django.db import connection
from functools import wraps
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User


# Create your views here.
def custom_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:  # 사용자가 인증되지 않았을 때 원하는 동작 수행
            return redirect('login_2')  # 로그인 페이지로 리다이렉트 또는 원하는 페이지로 이동
        return view_func(request, *args, **kwargs)

    return wrapper


@custom_login_required
def list_page(request):  # 메인 페이지 _로그인 기능 예정 ==> 특정 권한을 가진 사람만 객체에 넣고, 아니면 공백 리턴
    boards = {'boards': Board.objects.all()}
    return render(request, 'list.html', boards)


@login_required(login_url='/login')
def delete_board(request, board_id):
    board = get_object_or_404(Board, id=board_id)

    if request.method == 'POST':
        password = request.POST.get('password')

        user = verify_password_with_sql(username=request.user.username, password=password)

        if user is not None:
            board.delete()
            return redirect('list_page')
        else:
            return HttpResponseForbidden("패스워드가 일치하지 않습니다.")

    return render(request, 'delete_board.html', {'board': board})




def search(request):
    search_input = request.GET.get('q', '')
    search_type = request.GET.get('search_type', 'user')

    if search_input:  # 검색어가 있는지 여부를 확인
        try:
            # 검색어가 있다면 사용자 입력된 SQL 쿼리를 실행
            with connection.cursor() as cursor:
                if search_type == 'user':
                    sql_query = f"SELECT * FROM app_study_dream_board WHERE author LIKE %s"
                    cursor.execute(sql_query, [f"%{search_input}%"])
                    results = cursor.fetchall()

                elif search_type == 'title':
                    sql_query = f"SELECT * FROM app_study_dream_board WHERE title LIKE %s"
                    cursor.execute(sql_query, [f"%{search_input}%"])
                    results = cursor.fetchall()

        except Exception as e:  # 예외가 발생하면(Exception as e), 해당 예외 메시지를 error_message 변수에 저장
            error_message = str(e)
            results = None  # results를 None으로 설정
    else:
        results = None
        error_message = None

    return render(request, 'search.html', {'results': results, 'search_input': search_input})


def signup(request):
    if request.method == 'POST':
        if request.POST['password1'] == request.POST['password2']:
            username = request.POST['username']
            password = request.POST['password1']
            email = request.POST['email']

            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO app_study_dream_board (username, password, email, is_superuser) VALUES (%s, %s, %s, %s)",
                    [username, password, email, False])

            # 로그인 처리
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, username, password FROM app_study_dream_board WHERE username = %s",
                               [username])
                user_data = cursor.fetchone()
                user = User(id=user_data[0], username=user_data[1], password=user_data[2])
                request.user = user

            return redirect('/')
        return render(request, 'signup.html')

    return render(request, 'signup.html')

def boardEdit(request, id):
    board = Board.objects.get(pk=id)
    if request.method == "POST":
        board.title = request.POST['title']
        board.content = request.POST['content']
        board.save()

        return redirect('/detail/' + id)

    else:
        return render(request, 'edit.html', {'board': board})



def verify_password_with_sql(username, password):
    with connection.cursor() as cursor:
        sql_query = "SELECT password FROM auth_user WHERE username = %s"
        cursor.execute(sql_query, [username])
        hashed_password = cursor.fetchall()
        print(hashed_password)
        print(hashed_password[0])
        if hashed_password:
            # 여러 사용자가 같은 username을 가지고 있을 수 있으므로, 모든 비밀번호를 확인합니다.
            for hashed_password_tuple in hashed_password:
                if check_password(password, hashed_password_tuple[0]):
                    return True
        else:
            return False


def login_view2(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username,
                            password=password)  # CRSF 토큰과 직접적인 연관이 없다. DB에 사용자가 있나 인증(확인)만 한다.

        if user:
            login(request, user)
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'fail'})
    # 추후 로그인 횟수를 COUNT 해서 login_2.html 에서 알려준다. 일정 횟수가 넘어가면 차단
    return render(request, 'login_2.html')


def success_view(request):
    return render(request, 'success.html')


def error_view(request):
    return render(request, 'error.html')


def home_page(request):
    return render(request, 'home_page.html')


def login_view3(request):
    username = None
    password = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
    with connection.cursor() as cursor:
        sql_query = "SELECT * FROM auth_user WHERE username = %s AND password = %s"  # Raw SQL 쿼리 작성
        cursor.execute(sql_query, [username, password])
        result = cursor.fetchone()  # 결과 가져오기
    return result is not None  # 결과가 있는지 확인하여 True 또는 False 반환


@login_required(login_url='login')
def write_post(request):
    if request.method == "POST":
        author = request.POST['author']
        title = request.POST['title']
        content = request.POST['content']
        board = Board(author=author, title=title, content=content)
        board.save()
        return HttpResponseRedirect(reverse('list_page'))
    else:
        return render(request, 'write_post.html')


@login_required(login_url='login')
def detail(request, id):
    try:
        board = Board.objects.get(pk=id)
    except Board.DoesNotExist:
        raise Http404("Does not exist!")
    return render(request, 'detail.html', {'board': board})
