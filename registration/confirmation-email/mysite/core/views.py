from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib import messages
from django.core.mail import send_mail
from mysite.core.forms import SignUpForm
from mysite.core.tokens import account_activation_token
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import datetime

@login_required
def home(request):
    return render(request, 'home.html')

def forgetpassword(request):
    pass

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        email = request.POST['email']
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            from_email = settings.EMAIL_HOST_USER
            current_site = get_current_site(request)
            subject = 'Activate Your Account'
            message = render_to_string('account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            send_mail(subject,message,from_email,[email],fail_silently=True)
            return redirect('account_activation_sent')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})


def account_activation_sent(request):
    return render(request, 'account_activation_sent.html')


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.profile.email_confirmed = True
        user.save()
        login(request, user)
        return redirect('home')
    else:
        return render(request, 'account_activation_invalid.html')


def aes_encrypt(password, plaintext, base64=False):
    #Encryption
    import hashlib, os
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC 
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(BLOCK_SIZE) 
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext+chr(padding_length)*padding_length
    derived_key = password
    for i in range(0,DERIVATION_ROUNDS):
        derived_key = hashlib.sha256(derived_key+salt).digest()
    derived_key = derived_key[:KEY_SIZE]
    cipher_spec = AES.new(derived_key, MODE, iv)
    ciphertext = cipher_spec.encrypt(padded_plaintext)
    ciphertext = ciphertext + iv + salt
    if base64:
        import base64
        return base64.b64encode(ciphertext)
    else:
        return ciphertext.encode("hex")

def aes_decrypt(password, ciphertext, base64=False):
    #Decription
    import hashlib
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    if base64:
        import base64
        decoded_ciphertext = base64.b64decode(ciphertext)
    else:
        decoded_ciphertext = ciphertext.decode("hex")
    start_iv = len(decoded_ciphertext)-BLOCK_SIZE-SALT_LENGTH
    start_salt = len(decoded_ciphertext)-SALT_LENGTH
    data, iv, salt = decoded_ciphertext[:start_iv], decoded_ciphertext[start_iv:start_salt], decoded_ciphertext[start_salt:]
    derived_key = password
    for i in range(0, DERIVATION_ROUNDS):
        derived_key = hashlib.sha256(derived_key+salt).digest()
    derived_key = derived_key[:KEY_SIZE]
    cipher_spec = AES.new(derived_key, MODE, iv)
    plaintext_with_padding = cipher_spec.decrypt(data)
    padding_length = ord(plaintext_with_padding[-1])
    plaintext = plaintext_with_padding[:-padding_length]
    return plaintext


@csrf_exempt
def forgetpassword(request):
    """
    Forgot password functionality
    """
    temp_contente = {}
    if request.method == 'POST':
        email_address = request.POST['email_address']
        if email_address != "":
            emailcont = User.objects.filter(email=email_address).count()
            if emailcont == 1:
                user_content = User.objects.get(email=email_address)
                # Email Message Initialise
                i = datetime.datetime.now()
                current_date = i.strftime('%Y-%m-%d %H:%M:%S')
                re_date_count = user_content.email + '`' + current_date
                encoded = aes_encrypt("email", re_date_count)

                first_name_save = user_content.first_name
                site_url = settings.DOMAIN
                url_gen = '/accounts/verify/'
                reset_url = site_url + url_gen + encoded
                subject_content = 'Password Reset from Audiotube.'
                from_email = settings.EMAIL_HOST_USER

                message = render_to_string('forget-password-content.html', {
                'reset':reset_url
                })
                

                # send mail function
                try:
                    send_mail(subject_content,message,from_email,[email_address],fail_silently=True)
                except:
                    pass
            else:
                messages.error(request, 'Oops! Looks like this email address is not registered with Audiotube. Please enter a valid email address.')
    return render(request, 'lost-password.html')

@csrf_exempt
def reset_pass_red_view(request, emailaddr):
    """
    Args:
        emailaddr:  Encrypted(emailaddr+date)
    """
    if emailaddr != "":
        decoded = aes_decrypt("email", emailaddr)
        email_address_decode, date_decode = decoded.split('`')
        request.session['emailaddr'] = email_address_decode
        request.session['olddate'] = date_decode

        return redirect('reset_password_view')

@csrf_exempt
def reset_password_view(request):
    """
    Password Reset functioality
    """
    if('emailaddr' in request.session and 'olddate' in request.session):
        if(request.session['emailaddr'] != "" and request.session['olddate'] != ""):
            temp_contente = {}
            dat = request.session['olddate']
            d = datetime.datetime.strptime(dat, "%Y-%m-%d %H:%M:%S")
            end_date = d + datetime.timedelta(days=1)
            current_date = datetime.datetime.now()
            if end_date > current_date:
                if request.method == 'POST':
                    new_password = request.POST['password']
                    confirm_password = request.POST['confirm_password']
                    if (new_password == confirm_password and new_password != "" and confirm_password != ""):
                        session_email_address = request.session['emailaddr']
                        u = User.objects.get(email=session_email_address)
                        user_id = u.id
                        u = User.objects.get(id=user_id)
                        u.set_password(new_password)# set_password used for inserting password into database
                        u.save()
                        del request.session['emailaddr']
                        del request.session['olddate']

                        messages.success(request, 'Your password has been changed successfully. Please sign in with your new credentials.')
                        return redirect('home')
                    else:
                        return redirect('home')
            else:
                return redirect('forgetpassword')
        else:
            return redirect('forgetpassword')
        return render(request, 'reset-password.html', temp_contente)
    else:
        return redirect('forgetpassword')
