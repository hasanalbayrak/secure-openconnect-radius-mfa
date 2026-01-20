import radiusd
import json
import os
import requests
import random
import sys
import traceback
import logging
import bcrypt

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [AUTH] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger("vpn_auth")

# --- ENVIRONMENT VARIABLES ---
API_URL = "https://sms.verimor.com.tr/v2/send.json"
API_USER = os.environ.get('SMS_API_USER')
API_PASS = os.environ.get('SMS_API_PASS')
SOURCE_ADDR = os.environ.get('SMS_HEADER', 'VPN-AUTH')
USERS_FILE = "/etc/raddb/users.json"
TMP_OTP_DIR = "/tmp/otp_sessions"

if not os.path.exists(TMP_OTP_DIR):
    os.makedirs(TMP_OTP_DIR)

# --- UTILITIES ---

def mask_pii(data, visible_chars=2):
    """Masks Personally Identifiable Information in logs."""
    if not data or len(data) < 5:
        return "*****"
    return f"{data[:visible_chars]}*****{data[-visible_chars:]}"

def get_user_data(username):
    if not os.path.exists(USERS_FILE):
        logger.error(f"User database not found: {USERS_FILE}")
        return None
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
            return users.get(username)
    except Exception as e:
        logger.error(f"Error reading user database: {str(e)}")
        return None

def send_sms_otp(phone, otp_code, ref_code, user_info):
    """Sends the OTP via SMS Provider with a security reference code."""
    logger.info(f"Dispatching SMS to {mask_pii(phone)}. Ref: {ref_code}")
    
    headers = {'Content-Type': 'application/json'}
    
    # Construct personalized greeting
    full_name = f"{user_info.get('name', '')} {user_info.get('surname', '')}".strip()
    company = user_info.get('companyName', '')
    greeting = f"Dear {full_name} ({company})" if company else f"Dear {full_name}"

    # Message body
    message_text = (
        f"{greeting}, for security purposes please do not share this code. "
        f"Reference: {ref_code}. Your One-Time Password is: {otp_code}"
    )

    payload = {
        "username": API_USER,
        "password": API_PASS,
        "source_addr": SOURCE_ADDR,
        "messages": [
            { "msg": message_text, "dest": phone }
        ]
    }
    
    try:
        r = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        if r.status_code == 200:
            logger.info("SMS dispatched successfully.")
            return True
        else:
            logger.error(f"SMS Provider returned error. Status: {r.status_code}, Body: {r.text}")
            return False
    except Exception as e:
        logger.error(f"SMS Connection Exception: {str(e)}")
        return False

# --- RADIUS EVENT HANDLERS ---

def authorize(p):
    """Handles the initial authorization request."""
    try:
        username = None
        password = None
        state_exists = False
        
        # Parse packet attributes
        for item in p:
            if item[0] == 'User-Name': username = item[1]
            if item[0] == 'User-Password': password = item[1]
            if item[0] == 'State': state_exists = True

        # CASE 1: OTP Verification (State Attribute exists)
        if state_exists:
            # If state exists, this is the second leg of the auth.
            # Pass control to 'authenticate' function.
            return radiusd.RLM_MODULE_OK

        # CASE 2: Initial Login (Static Password Check)
        if not username: return radiusd.RLM_MODULE_REJECT

        # Convert password bytes to string
        if password and isinstance(password, bytes):
            try: password = password.decode('utf-8')
            except: pass

        user_data = get_user_data(username)
        if not user_data:
            logger.warning(f"Authentication failed: User '{username}' not found.")
            return radiusd.RLM_MODULE_REJECT

        stored_hash = user_data.get('password')
        if not stored_hash or not password:
            return radiusd.RLM_MODULE_REJECT

        # Verify Static Password using BCrypt
        try:
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                logger.info(f"Static password verified for user: {username}")
            else:
                logger.warning(f"Invalid static password for user: {username}")
                return radiusd.RLM_MODULE_REJECT
        except Exception as e:
            logger.error(f"BCrypt verification error: {e}")
            return radiusd.RLM_MODULE_REJECT

        # Generate Codes
        otp_code = str(random.randint(100000, 999999))
        ref_code = str(random.randint(100000, 999999))

        # Persist Session
        otp_file = os.path.join(TMP_OTP_DIR, username)
        with open(otp_file, 'w') as f:
            f.write(otp_code)

        # Prepare User Info
        user_info = {
            "name": user_data.get('name', username),
            "surname": user_data.get('surname', ''),
            "companyName": user_data.get('companyName', '')
        }

        # Send SMS and Challenge Client
        if send_sms_otp(user_data['phone'], otp_code, ref_code, user_info):
            vpn_message = f"Please enter the OTP. Security Reference: {ref_code}"
            
            reply_items = (
                ('Reply-Message', vpn_message),
                ('State', username.encode('utf-8')),
            )
            # RLM_MODULE_UPDATED triggers the Access-Challenge in default_site
            return (radiusd.RLM_MODULE_UPDATED, reply_items, None)
        else:
            return radiusd.RLM_MODULE_FAIL

    except Exception as e:
        logger.critical(f"Unhandled exception in authorize: {e}")
        traceback.print_exc(file=sys.stdout)
        return radiusd.RLM_MODULE_FAIL

def authenticate(p):
    """Handles the OTP verification phase."""
    try:
        username = None
        user_response = None
        
        for item in p:
            if item[0] == 'User-Name': username = item[1]
            if item[0] == 'User-Password': user_response = item[1]

        otp_file = os.path.join(TMP_OTP_DIR, username)
        if not os.path.exists(otp_file):
            logger.warning(f"OTP session expired or missing for user: {username}")
            return radiusd.RLM_MODULE_REJECT

        with open(otp_file, 'r') as f:
            saved_otp = f.read().strip()

        if isinstance(user_response, bytes):
            try: user_response = user_response.decode('utf-8')
            except: pass

        if user_response == saved_otp:
            logger.info(f"OTP verified. Access GRANTED for user: {username}")
            os.remove(otp_file) # Prevent replay attacks
            return radiusd.RLM_MODULE_OK
        else:
            logger.warning(f"Invalid OTP attempt for user: {username}")
            return radiusd.RLM_MODULE_REJECT

    except Exception as e:
        logger.critical(f"Unhandled exception in authenticate: {e}")
        return radiusd.RLM_MODULE_FAIL

# --- DUMMY HANDLERS FOR RADIUS COMPATIBILITY ---
def instantiate(p): logger.info("MFA Module Loaded."); return radiusd.RLM_MODULE_OK
def accounting(p): return radiusd.RLM_MODULE_OK
def pre_proxy(p): return radiusd.RLM_MODULE_OK
def post_proxy(p): return radiusd.RLM_MODULE_OK
def post_auth(p): return radiusd.RLM_MODULE_OK
def recv_coa(p): return radiusd.RLM_MODULE_OK
def send_coa(p): return radiusd.RLM_MODULE_OK
def detach(p): logger.info("MFA Module Unloaded."); return radiusd.RLM_MODULE_OK