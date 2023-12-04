from django.db import models


# Create your models here.
class Board(models.Model):
    author = models.CharField(max_length=10, null=False, blank=False )
    title = models.CharField(max_length=100, null=False, blank=False)
    content = models.TextField(null=False)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    record_score = models.TextField(default='your_default_value', null=False)

    def __str__(self):
        return self.title


class recorder(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)
    # user = CustomUser(username='사용자이름', password='비밀번호')
    # user.save()
    def __str__(self):
        return self.username