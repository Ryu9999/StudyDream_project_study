import threading
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, Http404, HttpResponse, JsonResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from app_study_dream.models import Board, Comment
from django.db import connection
from functools import wraps
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
import subprocess
from .models import Comment
from multiprocessing import Process


def custom_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return view_func(request, *args, **kwargs)

    return wrapper


def list_page(request):
    boards = {'boards': Board.objects.all()}
    return render(request, 'list.html', boards)


@custom_login_required
def delete_board(request, board_id):
    board = get_object_or_404(Board, id=board_id)
    print(board_id)
    if request.method == 'POST':
        password = request.POST.get('password')
        username = request.POST.get('username')
        print(password)
        print(username)
        user = verify_password_with_sql(username=username, password=password)
        if user:
            board.delete()
            return redirect('list_page')
        else:
            return HttpResponseForbidden("패스워드가 일치하지 않습니다.")
    return render(request, 'list.html', {'board': board})

@custom_login_required
def search(request):
    search_input = request.GET.get('q', '')
    search_type = request.GET.get('search_type', 'user')

    if search_input:
        with connection.cursor() as cursor:
            if search_type in ['user', 'title']:
                field_name = 'author' if search_type == 'user' else 'title'
                # 주의: 보안상의 이유로 사용자 입력에 대한 검증 없이 raw SQL 사용은 권장되지 않습니다.
                sql_query = f"SELECT * FROM app_study_dream_board WHERE {field_name} LIKE '%%{search_input}%%'"
                cursor.execute(sql_query)
                results = cursor.fetchall()

                context = {'results': results, 'search_input': search_input, 'search_type': search_type}
                return render(request, 'search.html', context)

    return render(request, 'search.html', {'search_input': search_input, 'search_type': search_type})



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
        if hashed_password:
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
        print(username)
        print(password)
        print(user)
        if user:
            login(request, user)
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'fail'})
    # 추후 로그인 횟수를 COUNT 해서 login_2.html 에서 알려준다. 일정 횟수가 넘어가면 차단
    return render(request, 'login_2.html')


# views.py
from django.shortcuts import render, HttpResponseRedirect, reverse
from .models import Board

@custom_login_required
def write_post(request):
    start_time_str = request.GET.get('start_time')
    end_time_str = request.GET.get('end_time')

    if request.method == "POST":
        # POST 요청일 때 폼 데이터 처리
        record_score = request.POST['studyScore']
        author = request.POST['author']
        title = request.POST['title']
        content = request.POST['content']

        if author == "" or title == "" or content == "" or record_score == "":
            return HttpResponseRedirect(reverse('list_page'))
        else:
            # Board 모델에 데이터 저장
            board = Board(record_score=record_score, author=author, title=title, content=content)
            board.save()
            return HttpResponseRedirect(reverse('list_page'))

    elif start_time_str and end_time_str:
        # GET 요청이면서 start_time과 end_time이 있는 경우
        from datetime import datetime
        start_time = datetime.fromisoformat(start_time_str)
        end_time = datetime.fromisoformat(end_time_str)

        time_difference = end_time - start_time
        time_difference_minutes = time_difference.total_seconds() / 60

        if time_difference_minutes < 1:
            time_difference_minutes = 0
        # 초를 시간, 분, 초로 변환
        hours, minutes = divmod(time_difference_minutes, 60)

        # time_difference_minutes가 60 이상인 경우 시간과 분으로 포맷팅
        if time_difference_minutes >= 60:
            time_difference_str = f'{int(hours)}시간 {int(minutes)}분'
        else:
            # 60 미만인 경우 분만 사용하여 포맷팅
            time_difference_str = f'{int(time_difference_minutes)}점'

        # record_score = time_difference_minutes

        # 템플릿에 변수 전달
        return render(request, 'write_post.html',
                      {'record_score': time_difference_str, 'time_difference_str': time_difference_str})

    else:
        # GET 요청이면서 start_time과 end_time이 없는 경우
        return render(request, 'write_post.html')

def signup(request):
    if request.method == 'POST':
        if request.POST['password1'] == request.POST['password2']:
            username = request.POST['username']
            raw_password = request.POST['password1']
            email = request.POST['email']

            try:
                hashed_password = make_password(raw_password)

                with connection.cursor() as cursor:
                    sql = "INSERT INTO auth_user ( username, password, email, is_superuser,first_name,last_name, is_staff, is_active, date_joined) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (
                        username, hashed_password, email, '', '', '', '', True, ''))  # is_active 값이 현재 사용하는 user인지 판별
                    connection.commit()

                return redirect('/')

            except Exception as e:
                connection.rollback()
                print("Failed. Try again. Error:", str(e))

        return render(request, 'signup.html')

    return render(request, 'signup.html')



@login_required(login_url='login')
def detail(request, id):
    try:
        board = Board.objects.get(pk=id)
    except Board.DoesNotExist:
        raise Http404("Does not exist!")
    return render(request, 'detail.html', {'board': board})

@csrf_exempt

def ping_counter(request):
    if request.method == "POST":
        command = request.POST.get('command', '')

        if command:
            try:
                ping_result = []

                def ping_thread():
                    nonlocal ping_result
                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    for line in process.stdout:
                        ping_result.append(line.rstrip())
                    process.terminate()  # 프로세스를 종료합니다.

                thread = threading.Thread(target=ping_thread)
                thread.start()
                thread.join()

                return JsonResponse({'ping_result': ping_result})

            except Exception as e:
                print(e)
                return JsonResponse({'error': str(e)})

    return render(request, 'ping_counter.html')



def comment_view(request):
    comments = {'comments': Comment.objects.all()}
    return render(request, 'comment.html', comments)


def add_comment(request):
    if request.method == 'POST':
        author = request.POST.get('author')
        text = request.POST.get('text')

        # Comment 테이블에 댓글 추가
        comment = Comment.objects.create(comments_author=author, comments=text)

        # 댓글 추가 후 댓글이 속한 게시글의 상세 페이지로 리다이렉트
        return redirect('comment_view')

    return render(request, 'list.html')