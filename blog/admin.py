from django.contrib import admin
from .models import BlogType, Blog
# Register your models here.

@admin.register(BlogType)
class BlogTypeAdmin(admin.ModelAdmin):
    list_display = ('id', 'type_name')

@admin.register(Blog)
class BlogAdmin(admin.ModelAdmin):
    list_display = ('id','title',  'content','author','get_read_num', 'created_time', 'last_updatedtime')

'''@admin.register(ReadNum)
class ReadNum(admin.ModelAdmin):
    list_display = ('read_num','blog')
'''        