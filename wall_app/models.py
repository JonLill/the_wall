from django.db import models
import re 

class UserManager(models.Manager):
    def basic_validator(self, post_data):
        errors = {}
        
        if(len(post_data['first_name']) < 2):
            errors['first_name'] = "First name must be atleast 2 characters"
        if(len(post_data['last_name']) < 2):
            errors['last_name'] = "Last name must be atleast 2 characters"
        

        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')  
        if not EMAIL_REGEX.match(post_data['email']):
            errors['email'] = "Invalid email address!"

        user = User.objects.filter(email=post_data['email'])
        if user:
            errors['email'] = "Email already used!"

        if(len(post_data['password']) > 64 or len(post_data['password']) < 8):
            errors['password'] = "Password must be 64 characters or less, and more than 8"
        if(post_data['confirm'] != post_data['password']):
            errors['password'] = "Passwords must match"

            
        return errors

class User(models.Model):
    first_name=models.CharField(max_length=225)
    last_name=models.CharField(max_length=225)
    email=models.CharField(max_length=225)
    password=models.CharField(max_length=225)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects=UserManager()

class Message(models.Model):
    user=models.ForeignKey(User, related_name="message", on_delete = models.CASCADE)
    content=models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Comment(models.Model):
    message=models.ForeignKey(Message, related_name="comment", on_delete = models.CASCADE)
    user=models.ForeignKey(User, related_name="comment", on_delete = models.CASCADE)
    content=models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



