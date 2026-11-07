from flask import Flask, render_template, request, redirect, url_for, flash
import os
from supabase import create_client, Client
from dotenv import load_dotenv

# I-load ang environment variables mula sa .env (para sa localhost)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-key")

# Pag-connect sa Supabase gamit ang credentials mula sa environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") # O kaya ay ANON_KEY depende sa setup mo
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        try:
            # I-trigger ang pagpapadala ng recovery email / OTP mula sa Supabase
            response = supabase.auth.reset_password_for_email(
                email,
                options={
                    "redirect_to": "http://127.0.0.1:5000/reset-password" # Palitan kapag naka-deploy na
                }
            )
            flash("Naipadala na ang password reset instructions sa iyong email.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"May nangyaring error: {str(e)}", "danger")
            
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('password')
        
        # Tandaan: Kadalasang kinukuha ng Supabase ang access token mula sa URL hash kapag nag-click ang user sa email link.
        # Maaari mong gamitin ang JavaScript sa frontend ng reset_password.html para makuha ang session token 
        # o gamitin ang updateUser API kapag naka-authenticate na ang user session.
        try:
            res = supabase.auth.update_user({"password": new_password})
            flash("Matagumpay na na-update ang iyong password!", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Hindi na-update ang password: {str(e)}", "danger")
            
    return render_template('reset_password.html')