from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import time
from threading import Thread
from instagrapi import Client
import os
import secrets
from datetime import datetime
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import json
import bcrypt  # Corrected from bcryptlara
from functools import wraps
import random
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging with detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('crm.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))  # Use env variable or generate once
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Enable template auto-reload for development

# Derive encryption key for password encryption
salt = b'instagram_crm_salt'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(app.secret_key.encode()))
fernet = Fernet(key)

# Load global proxy settings (optional, fallback if account-specific proxy not set)
try:
    with open('proxy.json', 'r') as f:
        proxy_data = json.load(f)
    proxy = proxy_data['proxies'][0]
    global_proxy_settings = {
        'http': proxy['http'],
        'username': proxy['username'],
        'password': proxy['password']
    }
except FileNotFoundError:
    logging.error("proxy.json not found, proceeding without global proxy")
    global_proxy_settings = None
except Exception as e:
    logging.error(f"Failed to load proxy.json: {str(e)}")
    global_proxy_settings = None

clients = {}

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter('strftime')
def _strftime(value, format="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return ""
    try:
        return datetime.fromtimestamp(int(value)).strftime(format)
    except (ValueError, TypeError) as e:
        logging.error(f"Failed to format timestamp {value}: {str(e)}")
        return ""

def init_db():
    try:
        conn = sqlite3.connect('crm.db')
        c = conn.cursor()
        # Create accounts table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS accounts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      username TEXT NOT NULL,
                      password_encrypted TEXT,
                      session_file TEXT,
                      needs_reauth INTEGER DEFAULT 0,
                      proxy TEXT,
                      UNIQUE(user_id, username),
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        # Add proxy column if it doesn't exist
        c.execute('PRAGMA table_info(accounts)')
        columns = [col[1] for col in c.fetchall()]
        if 'proxy' not in columns:
            c.execute('ALTER TABLE accounts ADD COLUMN proxy TEXT')
            logging.info("Added proxy column to accounts table")
        # Create dms table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS dms
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account_id INTEGER,
                      thread_id TEXT,
                      contact_name TEXT,
                      last_message TEXT,
                      timestamp INTEGER,
                      responded INTEGER DEFAULT 0,
                      seen INTEGER DEFAULT 0,
                      followup_sent INTEGER DEFAULT 0,
                      call_requested INTEGER DEFAULT 0,
                      is_system_message INTEGER DEFAULT 0,
                      FOREIGN KEY (account_id) REFERENCES accounts(id))''')
        # Add is_system_message column if it doesn't exist
        c.execute('PRAGMA table_info(dms)')
        columns = [col[1] for col in c.fetchall()]
        if 'is_system_message' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN is_system_message INTEGER DEFAULT 0')
        # Create users table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password_hash TEXT NOT NULL,
                      role TEXT NOT NULL DEFAULT 'customer',
                      credits INTEGER DEFAULT 0,
                      plan TEXT DEFAULT '')''')
        # Add credits and plan columns if they don't exist
        c.execute('PRAGMA table_info(users)')
        columns = [col[1] for col in c.fetchall()]
        if 'credits' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN credits INTEGER DEFAULT 0')
            logging.info("Added credits column to users table")
        if 'plan' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN plan TEXT DEFAULT ""')
            logging.info("Added plan column to users table")
        # Create dm_logs table for DM bot logs
        c.execute('''CREATE TABLE IF NOT EXISTS dm_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      account TEXT,
                      target TEXT,
                      message TEXT,
                      timestamp INTEGER,
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        # Create default super admin if not exists
        default_admin_username = 'admin'
        default_admin_password = 'supersecret123'  # Change this!
        hashed_password = bcrypt.hashpw(default_admin_password.encode(), bcrypt.gensalt()).decode()
        c.execute('SELECT id FROM users WHERE username = ?', (default_admin_username,))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                      (default_admin_username, hashed_password, 'admin', 0, ''))
        conn.commit()
        logging.info("Database initialized successfully")
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {str(e)}")
    finally:
        conn.close()

def encrypt_password(password):
    try:
        return fernet.encrypt(password.encode()).decode()
    except Exception as e:
        logging.error(f"Password encryption failed: {str(e)}")
        return None

def decrypt_password(encrypted_password):
    try:
        if encrypted_password is None:
            logging.error("Encrypted password is None")
            return None
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logging.error(f"Password decryption failed: {str(e)}")
        return None

def get_client(user_id, username):
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    c.execute('SELECT needs_reauth, session_file, password_encrypted, proxy FROM accounts WHERE user_id = ? AND username = ?', (user_id, username))
    result = c.fetchone()
    if not result:
        logging.error(f"Account {username} not found for user_id {user_id}")
        conn.close()
        return None
    needs_reauth, session_file, password_encrypted, proxy = result
    client_key = f"{user_id}_{username}"
    if needs_reauth and client_key in clients:
        del clients[client_key]
    if client_key not in clients:
        if not password_encrypted:
            logging.error(f"No encrypted password found for {username} (user_id {user_id})")
            c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
            conn.commit()
            conn.close()
            return None
        password = decrypt_password(password_encrypted)
        if not password:
            c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
            conn.commit()
            conn.close()
            return None
        cl = Client()
        # Apply proxy if set for the account, otherwise use global proxy or no proxy
        if proxy:
            try:
                proxy_parts = proxy.split(':')
                if len(proxy_parts) >= 4:
                    proxy_url = f"http://{proxy_parts[2]}:{proxy_parts[3]}@{proxy_parts[0]}:{proxy_parts[1]}"
                else:
                    proxy_url = f"http://{proxy}"
                cl.set_proxy(proxy_url)
                logging.info(f"Applied account-specific proxy for {username} (user_id {user_id}): {proxy_url}")
            except Exception as e:
                logging.error(f"Failed to apply account-specific proxy for {username} (user_id {user_id}): {str(e)}")
        elif global_proxy_settings:
            try:
                cl.set_proxy(
                    global_proxy_settings['http'],
                    username=global_proxy_settings['username'],
                    password=global_proxy_settings['password']
                )
                logging.info(f"Applied global proxy settings for {username} (user_id {user_id})")
            except Exception as e:
                logging.error(f"Failed to apply global proxy for {username} (user_id {user_id}): {str(e)}")
        try:
            if os.path.exists(session_file):
                cl.load_settings(session_file)
                cl.login(username, password)
                clients[client_key] = cl
                c.execute('UPDATE accounts SET needs_reauth = 0 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                logging.info(f"Session loaded successfully for {username} (user_id {user_id})")
            else:
                cl.login(username, password)
                cl.dump_settings(session_file)
                clients[client_key] = cl
                c.execute('UPDATE accounts SET needs_reauth = 0 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                logging.info(f"Authenticated and saved new session for {username} (user_id {user_id})")
        except Exception as e:
            logging.error(f"Failed to authenticate {username} (user_id {user_id}): {str(e)}")
            c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
            conn.commit()
            conn.close()
            return None
    conn.close()
    return clients.get(client_key)

def login_with_selenium(username, password, user_id):
    CHROMEDRIVER_PATH = "C:/chromedriver/chromedriver.exe"  # Update this path
    session_file = f"session_{user_id}_{username}.json"
    chrome_options = Options()
    chrome_options.add_argument("--disable-extensions")
    service = Service(CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    try:
        driver.get("https://www.instagram.com/accounts/login/")
        time.sleep(5)
        driver.find_element(By.NAME, "username").send_keys(username)
        driver.find_element(By.NAME, "password").send_keys(password)
        time.sleep(2)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(30)
        cookies = driver.get_cookies()
        with open(session_file, "w") as f:
            json.dump(cookies, f)
        logging.info(f"Selenium session saved successfully for {username} (user_id {user_id})")
    finally:
        driver.quit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login.html')
        conn = sqlite3.connect('crm.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, role, credits, plan FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            session['credits'] = user[4]
            session['plan'] = user[5]
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('credits', None)
    session.pop('plan', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                flash("Username and password are required.", "danger")
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                try:
                    c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                              (username, hashed_password, 'customer', 0, ''))
                    conn.commit()
                    flash(f"User {username} created successfully.", "success")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "danger")
        elif action == 'delete':
            user_id = request.form.get('user_id')
            c.execute('DELETE FROM users WHERE id = ? AND role != ?', (user_id, 'admin'))
            conn.commit()
            flash("User deleted successfully.", "success")
        elif action == 'assign_plan':
            user_id = request.form.get('user_id')
            plan = request.form.get('plan')
            plan_configs = {
                'plan1': {'credits': 100, 'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
                'plan2': {'credits': 300, 'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
                'plan3': {'credits': 500, 'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
            }
            if plan in plan_configs:
                c.execute('UPDATE users SET plan = ?, credits = ? WHERE id = ? AND role != ?',
                          (plan, plan_configs[plan]['credits'], user_id, 'admin'))
                conn.commit()
                flash(f"Plan {plan} assigned to user ID {user_id}.", "success")
            else:
                flash("Invalid plan selected.", "danger")
    c.execute('SELECT id, username, role, credits, plan FROM users')
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/login-with-selenium', methods=['GET', 'POST'])
@login_required
def login_with_selenium_route():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login_with_selenium.html')
        try:
            login_with_selenium(username, password, session['user_id'])
            flash(f"Selenium login completed for {username}. Please proceed to re-authenticate.", "success")
            return redirect(url_for('reauth_account', username=username))
        except Exception as e:
            flash(f"Failed to log in with Selenium: {str(e)}", "danger")
            logging.error(f"Failed to log in with Selenium for {username}: {str(e)}")
            return render_template('login_with_selenium.html')
    return render_template('login_with_selenium.html')

def check_dms():
    while True:
        try:
            conn = sqlite3.connect('crm.db')
            c = conn.cursor()
            c.execute('SELECT DISTINCT user_id, username FROM accounts WHERE needs_reauth = 0')
            accounts = c.fetchall()
            logging.debug(f"Checking DMs for {len(accounts)} accounts")
            for user_id, username in accounts:
                try:
                    cl = get_client(user_id, username)
                    if not cl:
                        logging.warning(f"Skipping {username} (user_id {user_id}) due to invalid session")
                        continue
                    cl_user_id = cl.user_id
                    threads = cl.direct_threads(amount=50)
                    thread_dict = {thread.id: thread for thread in threads}
                    threads = list(thread_dict.values())
                    logging.info(f"Fetched {len(threads)} threads for {username} (user_id {user_id})")
                    for thread in threads:
                        if not thread.messages:
                            logging.debug(f"Thread {thread.id} has no messages, skipping")
                            continue
                        last_message = thread.messages[0].text.lower().strip()
                        contact_name = thread.users[0].username
                        timestamp = int(thread.messages[0].timestamp.timestamp())
                        is_user_message = thread.messages[0].user_id != cl_user_id
                        logging.debug(f"Thread {thread.id} - Contact: {contact_name}, Message: {last_message}, Is User Message: {is_user_message}")
                        seen = 0
                        recipient_id = thread.users[0].pk
                        if thread.last_seen_at and str(recipient_id) in thread.last_seen_at:
                            last_seen_info = thread.last_seen_at[str(recipient_id)]
                            last_seen_timestamp = (
                                int(last_seen_info.get('timestamp', 0))
                                if isinstance(last_seen_info, dict)
                                else int(last_seen_info.timestamp())
                            )
                            seen = 1 if last_seen_timestamp >= timestamp else 0
                            logging.debug(f"Thread {thread.id} - Last Seen Timestamp: {last_seen_timestamp}, Message Timestamp: {timestamp}, Seen: {seen}")
                        c.execute('SELECT id, timestamp, responded, followup_sent, call_requested, is_system_message FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', (thread.id, user_id, username))
                        existing = c.fetchone()
                        is_system_message = 0 if is_user_message else 1
                        if existing:
                            existing_id, existing_timestamp, existing_responded, existing_followup_sent, existing_call_requested, existing_is_system = existing
                            if existing_timestamp >= timestamp and existing_is_system == is_system_message:
                                logging.debug(f"Thread {thread.id} for {username} (user_id {user_id}): message already processed (existing timestamp: {existing_timestamp}, new timestamp: {timestamp})")
                                continue
                            c.execute('''
                                UPDATE dms 
                                SET contact_name = ?, last_message = ?, timestamp = ?, seen = ?, is_system_message = ? 
                                WHERE thread_id = ? 
                                AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)
                            ''', (contact_name, last_message, timestamp, seen, is_system_message, thread.id, user_id, username))
                            logging.debug(f"Updated DM for thread {thread.id} for {username} (user_id {user_id})")
                        else:
                            c.execute('''
                                INSERT INTO dms (account_id, thread_id, contact_name, last_message, timestamp, responded, seen, followup_sent, call_requested, is_system_message)
                                VALUES ((SELECT id FROM accounts WHERE user_id = ? AND username = ?), ?, ?, ?, ?, 0, ?, 0, 0, ?)
                            ''', (user_id, username, thread.id, contact_name, last_message, timestamp, seen, is_system_message))
                            logging.debug(f"Inserted new DM for thread {thread.id} for {username} (user_id {user_id})")
                        c.execute('SELECT responded, followup_sent, call_requested FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', (thread.id, user_id, username))
                        responded, followup_sent, call_requested = c.fetchone()
                        if is_user_message and responded == 0:
                            if any(word in last_message for word in ['hola']):
                                logging.info(f"Detected keyword 'hola' from {contact_name} (thread {thread.id}) for {username} (user_id {user_id})")
                                cl.direct_send("Se que te deben llegar muchos mensajes como estos, la verdad", thread_ids=[thread.id])
                                cl.direct_send("Se que la prospección puede ser agotadora, pero el mes pasado hicimos mas de 30kUSD/mes con un cliente de 800 seguidores en tu mismo rubro, te comparto la captura de su cuenta de banco por aqui", thread_ids=[thread.id])
                                cl.direct_send("Estoy convencido que en el mundo de las marcas personales y klanten van diensten, este sistema es de los mejores ya que no hace falta que tengas que depender del contenido orgánico y de llamadas de venta", thread_ids=[thread.id])
                                c.execute('UPDATE dms SET responded = 1 WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', (thread.id, user_id, username))
                                logging.info(f"Sent predefined sequence to {contact_name} (thread {thread.id}) for {username} (user_id {user_id})")
                except Exception as e:
                    logging.error(f"DM processing error for {username} (user_id {user_id}): {str(e)}")
                finally:
                    time.sleep(1)
            conn.commit()
        except Exception as e:
            logging.error(f"check_dms loop error: {str(e)}")
        finally:
            conn.close()
        time.sleep(30)

@app.route('/', defaults={'selected_account': None})
@app.route('/<selected_account>')
@login_required
def dashboard(selected_account):
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    user_id = session['user_id']
    role = session['role']
    # Admin sees all accounts, customers see only their own
    if role == 'admin':
        c.execute('SELECT username, needs_reauth FROM accounts')
    else:
        c.execute('SELECT username, needs_reauth FROM accounts WHERE user_id = ?', (user_id,))
    accounts = c.fetchall()
    for username, needs_reauth in accounts:
        if needs_reauth:
            flash(f"Session for {username} has expired. Please re-authenticate the account.", "danger")
    valid_usernames = [acc[0] for acc in accounts]
    if selected_account and selected_account not in valid_usernames:
        flash("Invalid account selected.", "danger")
        selected_account = None
    if selected_account:
        c.execute('SELECT id FROM accounts WHERE user_id = ? AND username = ?', (user_id, selected_account) if role != 'admin' else (None, selected_account))
        result = c.fetchone()
        if not result:
            flash("Selected account not found.", "danger")
            conn.close()
            return redirect(url_for('dashboard'))
        account_id = result[0]
        c.execute('SELECT * FROM dms WHERE account_id = ? ORDER BY timestamp DESC LIMIT 10', (account_id,))
        dms = c.fetchall()
        c.execute('''
            SELECT DISTINCT contact_name 
            FROM dms 
            WHERE account_id = ? 
            AND responded = 0 
            AND followup_sent = 0 
            AND is_system_message = 0 
            AND timestamp > ?
            GROUP BY thread_id
        ''', (account_id, int(time.time()) - 86400))
        non_responders = list(set(row[0] for row in c.fetchall()))
        # Count total chats for the selected account
        c.execute('SELECT COUNT(DISTINCT thread_id) FROM dms WHERE account_id = ?', (account_id,))
        total_chats = c.fetchone()[0]
    else:
        if role == 'admin':
            c.execute('SELECT * FROM dms ORDER BY timestamp DESC LIMIT 10')
        else:
            c.execute('SELECT * FROM dms WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ?) ORDER BY timestamp DESC LIMIT 10', (user_id,))
        dms = c.fetchall()
        if role == 'admin':
            c.execute('''
                SELECT DISTINCT contact_name 
                FROM dms 
                WHERE responded = 0 
                AND followup_sent = 0 
                AND is_system_message = 0 
                AND timestamp > ?
                GROUP BY thread_id
            ''', (int(time.time()) - 86400,))
        else:
            c.execute('''
                SELECT DISTINCT contact_name 
                FROM dms 
                WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ?)
                AND responded = 0 
                AND followup_sent = 0 
                AND is_system_message = 0 
                AND timestamp > ?
                GROUP BY thread_id
            ''', (user_id, int(time.time()) - 86400))
        non_responders = list(set(row[0] for row in c.fetchall()))
        # Count total chats for all accounts
        if role == 'admin':
            c.execute('SELECT COUNT(DISTINCT thread_id) FROM dms')
        else:
            c.execute('SELECT COUNT(DISTINCT thread_id) FROM dms WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ?)', (user_id,))
        total_chats = c.fetchone()[0]
    # Fetch user's credits and plan
    c.execute('SELECT credits, plan FROM users WHERE id = ?', (user_id,))
    user_info = c.fetchone()
    credits, plan = user_info if user_info else (0, '')
    debug_timestamp = int(time.time())
    logging.debug(f"Dashboard rendered for user_id {user_id} - Selected: {selected_account}, Non-Responders: {len(non_responders)}, DMs: {len(dms)}, Total Chats: {total_chats}, Credits: {credits}, Plan: {plan}")
    conn.close()
    return render_template('dashboard.html', accounts=accounts, dms=dms, non_responders=non_responders, selected_account=selected_account, debug_timestamp=debug_timestamp, credits=credits, plan=plan, total_chats=total_chats)

@app.route('/inbox', defaults={'selected_account': None})
@app.route('/inbox/<selected_account>')
@login_required
def inbox(selected_account):
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    user_id = session['user_id']
    role = session['role']
    # Fetch accounts
    if role == 'admin':
        c.execute('SELECT username, needs_reauth FROM accounts')
    else:
        c.execute('SELECT username, needs_reauth FROM accounts WHERE user_id = ?', (user_id,))
    accounts = c.fetchall()
    valid_usernames = [acc[0] for acc in accounts]
    
    # If no selected_account, default to the first account or None
    if not selected_account and accounts:
        selected_account = accounts[0][0]
    elif selected_account not in valid_usernames:
        flash("Invalid account selected.", "danger")
        selected_account = accounts[0][0] if accounts else None
    
    threads = []
    total_chats = 0
    if selected_account:
        # Fetch account ID
        c.execute('SELECT id FROM accounts WHERE username = ?' + (' AND user_id = ?' if role != 'admin' else ''), 
                  (selected_account, user_id) if role != 'admin' else (selected_account,))
        result = c.fetchone()
        if result:
            account_id = result[0]
            # Fetch distinct threads for the selected account
            c.execute('''
                SELECT DISTINCT thread_id, contact_name, last_message, timestamp, seen, responded, followup_sent, is_system_message 
                FROM dms 
                WHERE account_id = ? 
                ORDER BY timestamp DESC
            ''', (account_id,))
            threads = c.fetchall()
            # Count total chats
            c.execute('SELECT COUNT(DISTINCT thread_id) FROM dms WHERE account_id = ?', (account_id,))
            total_chats = c.fetchone()[0]
        else:
            flash("Selected account not found.", "danger")
    
    # Fetch user's credits and plan
    c.execute('SELECT credits, plan FROM users WHERE id = ?', (user_id,))
    user_info = c.fetchone()
    credits, plan = user_info if user_info else (0, '')
    logging.debug(f"Inbox rendered for user_id {user_id} - Selected: {selected_account}, Threads: {len(threads)}, Total Chats: {total_chats}")
    conn.close()
    return render_template('inbox.html', accounts=accounts, threads=threads, selected_account=selected_account, total_chats=total_chats, credits=credits, plan=plan)

@app.route('/api/dms/<account>')
@login_required
def get_dms(account):
    user_id = session['user_id']
    role = session['role']
    try:
        conn = sqlite3.connect('crm.db')
        c = conn.cursor()
        # Verify account exists and belongs to user (unless admin)
        c.execute('SELECT id FROM accounts WHERE username = ?' + (' AND user_id = ?' if role != 'admin' else ''), 
                  (account, user_id) if role != 'admin' else (account,))
        result = c.fetchone()
        if not result:
            return jsonify([]), 403
        account_id = result[0]
        # Fetch distinct threads
        c.execute('''
            SELECT DISTINCT thread_id, contact_name, last_message, timestamp, seen, responded, followup_sent, is_system_message 
            FROM dms 
            WHERE account_id = ? 
            ORDER BY timestamp DESC
        ''', (account_id,))
        threads = [
            {
                'thread_id': row[0],
                'contact_name': row[1],
                'last_message': row[2],
                'timestamp': row[3],
                'seen': bool(row[4]),
                'responded': bool(row[5]),
                'followup_sent': bool(row[6]),
                'is_system_message': bool(row[7])
            } for row in c.fetchall()
        ]
        conn.close()
        return jsonify(threads)
    except Exception as e:
        logging.error(f"Error fetching DMs for account {account}: {str(e)}")
        return jsonify([]), 500

@app.route('/add-account', methods=['GET', 'POST'])
@login_required
def add_account():
    logging.info(f"Accessing /add-account with method {request.method}")
    user_id = session['user_id']
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        proxy = request.form.get('proxy', '').strip()
        two_factor_code = request.form.get('two_factor_code', '')
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        # Check user's plan and credits
        conn = sqlite3.connect('crm.db')
        c = conn.cursor()
        c.execute('SELECT plan, credits FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found.", "danger")
            conn.close()
            return render_template('add_account.html', two_factor_required=False)
        plan, credits = user
        plan_configs = {
            'plan1': {'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
            'plan2': {'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
            'plan3': {'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            flash("You must have an active plan to add accounts.", "danger")
            conn.close()
            return render_template('add_account.html', two_factor_required=False)
        # Check account limit
        c.execute('SELECT COUNT(*) FROM accounts WHERE user_id = ?', (user_id,))
        current_accounts = c.fetchone()[0]
        if current_accounts >= plan_configs[plan]['max_accounts']:
            flash(f"You have reached the maximum number of accounts ({plan_configs[plan]['max_accounts']}) for your plan.", "danger")
            conn.close()
            return render_template('add_account.html', two_factor_required=False)
        # Check credits
        credits_needed = plan_configs[plan]['credits_per_account']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to add an account, but you have {credits}.", "danger")
            conn.close()
            return render_template('add_account.html', two_factor_required=False)
        client_key = f"{user_id}_{username}"
        if client_key in clients:
            del clients[client_key]
        cl = Client()
        # Apply proxy if provided
        if proxy:
            try:
                proxy_parts = proxy.split(':')
                if len(proxy_parts) >= 4:
                    proxy_url = f"http://{proxy_parts[2]}:{proxy_parts[3]}@{proxy_parts[0]}:{proxy_parts[1]}"
                else:
                    proxy_url = f"http://{proxy}"
                cl.set_proxy(proxy_url)
                logging.info(f"Setting proxy for {username} (user_id {user_id}): {proxy_url}")
            except Exception as e:
                flash(f"Invalid proxy format: {str(e)}", "danger")
                logging.error(f"Invalid proxy format for {username} (user_id {user_id}): {str(e)}")
                conn.close()
                return render_template('add_account.html', two_factor_required=False)
        elif global_proxy_settings:
            try:
                cl.set_proxy(
                    global_proxy_settings['http'],
                    username=global_proxy_settings['username'],
                    password=global_proxy_settings['password']
                )
                logging.info(f"Applied global proxy for {username} (user_id {user_id})")
            except Exception as e:
                logging.error(f"Failed to apply global proxy for {username} (user_id {user_id}): {str(e)}")
        try:
            session_file = f'session_{user_id}_{username}.json'
            password_encrypted = encrypt_password(password)
            if not password_encrypted:
                flash("Password encryption failed.", "danger")
                conn.close()
                return render_template('add_account.html', two_factor_required=False)
            if os.path.exists(session_file):
                os.remove(session_file)
            if two_factor_code:
                cl.login(username, password, verification_code=two_factor_code)
            else:
                cl.login(username, password)
            cl.dump_settings(session_file)
            # Deduct credits and save account
            new_credits = credits - credits_needed
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            c.execute('INSERT OR REPLACE INTO accounts (user_id, username, password_encrypted, session_file, needs_reauth, proxy) VALUES (?, ?, ?, ?, 0, ?)',
                     (user_id, username, password_encrypted, session_file, proxy or None))
            conn.commit()
            conn.close()
            clients[client_key] = cl
            session['credits'] = new_credits  # Update session credits
            flash(f"Account '{username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}", "success")
            logging.info(f"Account {username} added successfully for user_id {user_id}, proxy: {proxy or 'none'}, credits deducted: {credits_needed}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            if "challenge_required" in str(e):
                flash("Two-factor authentication required. Please enter the 2FA code.", "warning")
                conn.close()
                return render_template('add_account.html', username=username, two_factor_required=True)
            flash(f"Failed to add account: {str(e)}", "danger")
            logging.error(f"Failed to add account {username} for user_id {user_id}: {str(e)}")
            conn.close()
            return render_template('add_account.html', two_factor_required=False)
    return render_template('add_account.html', two_factor_required=False)

@app.route('/reauth-account/<username>', methods=['GET', 'POST'])
@login_required
def reauth_account(username):
    user_id = session['user_id']
    role = session['role']
    logging.info(f"Accessing /reauth-account/{username} with method {request.method} for user_id {user_id}")
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    if role != 'admin':
        c.execute('SELECT id FROM accounts WHERE user_id = ? AND username = ?', (user_id, username))
        if not c.fetchone():
            flash("You do not have permission to re-authenticate this account.", "danger")
            conn.close()
            return redirect(url_for('dashboard'))
    conn.close()
    if request.method == 'POST':
        password = request.form.get('password')
        two_factor_code = request.form.get('two_factor_code', '')
        if not password:
            flash("Password is required.", "danger")
            return render_template('reauth_account.html', username=username, two_factor_required=False)
        cl = Client()
        try:
            session_file = f'session_{user_id}_{username}.json' if role != 'admin' else f'session_admin_{username}.json'
            password_encrypted = encrypt_password(password)
            if not password_encrypted:
                flash("Password encryption failed.", "danger")
                return render_template('reauth_account.html', username=username, two_factor_required=False)
            if os.path.exists(session_file):
                os.remove(session_file)
            if two_factor_code:
                cl.login(username, password, verification_code=two_factor_code)
            else:
                cl.login(username, password)
            cl.dump_settings(session_file)
            conn = sqlite3.connect('crm.db')
            c = conn.cursor()
            if role == 'admin':
                c.execute('UPDATE accounts SET password_encrypted = ?, session_file = ?, needs_reauth = 0 WHERE username = ?',
                         (password_encrypted, session_file, username))
            else:
                c.execute('UPDATE accounts SET password_encrypted = ?, session_file = ?, needs_reauth = 0 WHERE user_id = ? AND username = ?',
                         (password_encrypted, session_file, user_id, username))
            conn.commit()
            conn.close()
            client_key = f"{user_id}_{username}" if role != 'admin' else f"admin_{username}"
            if client_key in clients:
                del clients[client_key]
            clients[client_key] = cl
            flash(f"Account '{username}' re-authenticated successfully!", "success")
            logging.info(f"Account {username} re-authenticated successfully for user_id {user_id}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            if "challenge_required" in str(e):
                flash("Two-factor authentication required. Please enter the 2FA code.", "warning")
                return render_template('reauth_account.html', username=username, two_factor_required=True)
            flash(f"Failed to re-authenticate account: {str(e)}", "danger")
            logging.error(f"Failed to re-authenticate account {username} for user_id {user_id}: {str(e)}")
            return render_template('reauth_account.html', username=username, two_factor_required=False)
    return render_template('reauth_account.html', username=username, two_factor_required=False)

@app.route('/send-dms', methods=['GET', 'POST'])
@login_required
def send_dms():
    user_id = session['user_id']
    role = session['role']
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    if role == 'admin':
        c.execute('SELECT username, needs_reauth FROM accounts')
    else:
        c.execute('SELECT username, needs_reauth FROM accounts WHERE user_id = ?', (user_id,))
    accounts = c.fetchall()
    if request.method == 'POST':
        account = request.form.get('account')
        usernames_file = request.files.get('usernames')
        messages_file = request.files.get('messages')
        if not account or not usernames_file or not messages_file:
            flash("Account, usernames file, and messages file are required.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Verify account exists and belongs to user (unless admin)
        c.execute('SELECT id FROM accounts WHERE username = ?' + (' AND user_id = ?' if role != 'admin' else ''), 
                  (account, user_id) if role != 'admin' else (account,))
        if not c.fetchone():
            flash("Invalid account selected.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Check user's plan and credits
        c.execute('SELECT plan, credits FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        plan, credits = user
        plan_configs = {
            'plan1': {'credits_per_dm': 1},
            'plan2': {'credits_per_dm': 1},
            'plan3': {'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            flash("You must have an active plan to send DMs.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Read usernames
        try:
            usernames = usernames_file.read().decode('utf-8').strip().splitlines()
            usernames = [u.strip() for u in usernames if u.strip()]
        except Exception as e:
            flash(f"Failed to read usernames file: {str(e)}", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Read messages
        try:
            messages_data = json.load(messages_file)
            messages = messages_data if isinstance(messages_data, list) else []
            if not messages:
                raise ValueError("Messages file is empty or invalid")
        except Exception as e:
            flash(f"Failed to read messages file: {str(e)}", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Check credits
        credits_needed = len(usernames) * plan_configs[plan]['credits_per_dm']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to send {len(usernames)} DMs, but you have {credits}.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        # Send DMs
        cl = get_client(user_id if role != 'admin' else 0, account)
        if not cl:
            flash(f"Cannot send DMs for {account}: Session expired.", "danger")
            conn.close()
            return render_template('index.html', accounts=accounts)
        sent_count = 0
        try:
            for username in usernames:
                try:
                    user_id_target = cl.user_id_from_username(username)
                    message = random.choice(messages)
                    cl.direct_send(message, [user_id_target])
                    # Log the DM
                    timestamp = int(time.time())
                    c.execute('INSERT INTO dm_logs (user_id, account, target, message, timestamp) VALUES (?, ?, ?, ?, ?)',
                              (user_id, account, username, message, timestamp))
                    sent_count += 1
                    logging.info(f"Sent DM to {username} from {account} (user_id {user_id}): {message}")
                    time.sleep(1)  # Avoid rate limits
                except Exception as e:
                    logging.error(f"Failed to send DM to {username} from {account}: {str(e)}")
                    flash(f"Failed to send DM to {username}: {str(e)}", "warning")
            # Deduct credits
            new_credits = credits - (sent_count * plan_configs[plan]['credits_per_dm'])
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            conn.commit()
            session['credits'] = new_credits
            if sent_count > 0:
                flash(f"Sent {sent_count} DMs successfully! {sent_count * plan_configs[plan]['credits_per_dm']} credits deducted. Remaining credits: {new_credits}", "success")
            else:
                flash("No DMs sent.", "info")
        except Exception as e:
            logging.error(f"Error sending DMs: {str(e)}")
            flash(f"Error sending DMs: {str(e)}", "danger")
        finally:
            conn.close()
        return render_template('index.html', accounts=accounts)
    conn.close()
    return render_template('index.html', accounts=accounts)

@app.route('/dm-logs')
@login_required
def dm_logs():
    user_id = session['user_id']
    role = session['role']
    try:
        conn = sqlite3.connect('crm.db')
        c = conn.cursor()
        if role == 'admin':
            c.execute('SELECT account, target, message, timestamp FROM dm_logs ORDER BY timestamp DESC LIMIT 50')
        else:
            c.execute('SELECT account, target, message, timestamp FROM dm_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50', (user_id,))
        logs = [{'account': row[0], 'target': row[1], 'message': row[2], 'timestamp': row[3]} for row in c.fetchall()]
        conn.close()
        return jsonify(logs)
    except Exception as e:
        logging.error(f"Error fetching DM logs: {str(e)}")
        return jsonify([]), 500

@app.route('/send-followup', methods=['POST'])
@login_required
def send_followup():
    followup = request.form.get('followup')
    selected_account = request.form.get('selected_account')
    user_id = session['user_id']
    role = session['role']
    # Check user's plan and credits
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    c.execute('SELECT plan, credits FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if not user:
        flash("User not found.", "danger")
        conn.close()
        return redirect(url_for('dashboard', selected_account=selected_account))
    plan, credits = user
    plan_configs = {
        'plan1': {'credits_per_dm': 1},
        'plan2': {'credits_per_dm': 1},
        'plan3': {'credits_per_dm': 1}
    }
    if not plan or plan not in plan_configs:
        flash("You must have an active plan to send follow-ups.", "danger")
        conn.close()
        return redirect(url_for('dashboard', selected_account=selected_account))
    if not followup:
        flash("Follow-up message cannot be empty!", "danger")
        conn.close()
        return redirect(url_for('dashboard', selected_account=selected_account))
    try:
        if selected_account:
            if role == 'admin':
                c.execute('SELECT id FROM accounts WHERE username = ?', (selected_account,))
            else:
                c.execute('SELECT id FROM accounts WHERE user_id = ? AND username = ?', (user_id, selected_account))
            account = c.fetchone()
            if not account:
                flash("Invalid account selected.", "danger")
                conn.close()
                return redirect(url_for('dashboard'))
            account_id = account[0]
            c.execute('''
                SELECT DISTINCT dms.thread_id, dms.contact_name, accounts.username 
                FROM dms 
                JOIN accounts ON dms.account_id = accounts.id 
                WHERE dms.account_id = ? 
                AND dms.responded = 0 
                AND dms.followup_sent = 0 
                AND dms.is_system_message = 0 
                AND dms.timestamp > ?
                GROUP BY dms.thread_id
            ''', (account_id, int(time.time()) - 86400))
        else:
            if role == 'admin':
                c.execute('''
                    SELECT DISTINCT dms.thread_id, dms.contact_name, accounts.username 
                    FROM dms 
                    JOIN accounts ON dms.account_id = accounts.id 
                    WHERE dms.responded = 0 
                    AND dms.followup_sent = 0 
                    AND dms.is_system_message = 0 
                    AND dms.timestamp > ?
                    GROUP BY dms.thread_id
                ''', (int(time.time()) - 86400,))
            else:
                c.execute('''
                    SELECT DISTINCT dms.thread_id, dms.contact_name, accounts.username 
                    FROM dms 
                    JOIN accounts ON dms.account_id = accounts.id 
                    WHERE accounts.user_id = ?
                    AND dms.responded = 0 
                    AND dms.followup_sent = 0 
                    AND dms.is_system_message = 0 
                    AND dms.timestamp > ?
                    GROUP BY dms.thread_id
                ''', (user_id, int(time.time()) - 86400))
        threads = c.fetchall()
        credits_needed = len(threads) * plan_configs[plan]['credits_per_dm']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to send {len(threads)} follow-ups, but you have {credits}.", "danger")
            conn.close()
            return redirect(url_for('dashboard', selected_account=selected_account))
        sent_count = 0
        for thread_id, contact_name, username in threads:
            cl = get_client(user_id if role != 'admin' else 0, username)
            if cl:
                try:
                    cl.direct_send(followup, thread_ids=[thread_id])
                    c.execute('''
                        UPDATE dms 
                        SET followup_sent = 1, is_system_message = 1 
                        WHERE thread_id = ? 
                        AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)
                    ''', (thread_id, user_id if role != 'admin' else 0, username))
                    # Log the follow-up as a DM
                    timestamp = int(time.time())
                    c.execute('INSERT INTO dm_logs (user_id, account, target, message, timestamp) VALUES (?, ?, ?, ?, ?)',
                              (user_id, username, contact_name, followup, timestamp))
                    sent_count += 1
                    logging.info(f"Sent follow-up to {contact_name} (thread {thread_id}) for {username} (user_id {user_id})")
                except Exception as e:
                    logging.error(f"Failed to send follow-up to {contact_name} (thread {thread_id}) for {username}: {str(e)}")
                    flash(f"Failed to send follow-up to {contact_name}: {str(e)}", "warning")
            else:
                flash(f"Cannot send follow-up for {username}: Session expired.", "danger")
                logging.warning(f"Cannot send follow-up for {username}: Session expired")
        # Deduct credits
        new_credits = credits - (sent_count * plan_configs[plan]['credits_per_dm'])
        c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
        conn.commit()
        session['credits'] = new_credits
        if sent_count > 0:
            flash(f"Follow-up messages sent to {sent_count} non-responders! {sent_count * plan_configs[plan]['credits_per_dm']} credits deducted. Remaining credits: {new_credits}", "success")
        else:
            flash("No follow-up messages sent. No eligible non-responders found.", "info")
    except Exception as e:
        logging.exception("An unexpected error occurred in /send-followup")
        flash("An unexpected error occurred. Please try again later.", "danger")
    finally:
        conn.close()
    return redirect(url_for('dashboard', selected_account=selected_account))

@app.route('/delete-account/<username>', methods=['POST'])
@login_required
def delete_account(username):
    user_id = session['user_id']
    role = session['role']
    conn = sqlite3.connect('crm.db')
    c = conn.cursor()
    if role != 'admin':
        c.execute('SELECT id FROM accounts WHERE user_id = ? AND username = ?', (user_id, username))
        if not c.fetchone():
            flash("You do not have permission to delete this account.", "danger")
            conn.close()
            return redirect(url_for('dashboard'))
    c.execute('DELETE FROM accounts WHERE user_id = ? AND username = ?' if role != 'admin' else 'DELETE FROM accounts WHERE username = ?', 
              (user_id, username) if role != 'admin' else (username,))
    c.execute('DELETE FROM dms WHERE account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)' if role != 'admin' else 
              'DELETE FROM dms WHERE account_id = (SELECT id FROM accounts WHERE username = ?)', 
              (user_id, username) if role != 'admin' else (username,))
    conn.commit()
    conn.close()
    session_file = f'session_{user_id}_{username}.json' if role != 'admin' else f'session_admin_{username}.json'
    if os.path.exists(session_file):
        os.remove(session_file)
    client_key = f"{user_id}_{username}" if role != 'admin' else f"admin_{username}"
    clients.pop(client_key, None)
    flash(f"Account {username} deleted successfully.", "success")
    logging.info(f"Account {username} deleted for user_id {user_id}")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    Thread(target=check_dms, daemon=True).start()
    app.run(debug=False, host='0.0.0.0', port=5000)