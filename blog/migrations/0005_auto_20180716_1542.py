# Generated by Django 2.0.3 on 2018-07-16 07:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0004_readnum'),
    ]

    operations = [
        migrations.RenameField(
            model_name='readnum',
            old_name='read',
            new_name='read_num',
        ),
    ]
