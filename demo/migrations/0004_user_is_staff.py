# Generated by Django 2.0 on 2020-06-13 11:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('demo', '0003_user_is_superuser'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False, verbose_name='staff status'),
        ),
    ]
