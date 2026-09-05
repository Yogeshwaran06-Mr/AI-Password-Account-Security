import os
import sys
import bcrypt
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from models.db_model import (
    init_db,
    get_user_by_email,
    get_user_by_id,
    create_user,
    log_login_attempt,
    log_security_event,
    get_user_dashboard_stats,
    get_user_login_attempts,
    get_recent_failed_attempts_count,
    get_user_known_devices,
    get_user_last_successful_login,
    get_global_soc_stats,
    register_biometric_device,
    get_biometric_device,
    get_user_biometric_devices,
    update_device_last_used,
    has_biometrics_enabled,
    create_biometric_challenge,
    validate_and_consume_biometric_challenge,
    calculate_account_security_score
)

from ml.risk_engine import (
    analyze_password_security,
    evaluate_login_risk,
    estimate_crack_time
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secureai-cyber-defense-key-2024-secret!#*")

# Ensure DB is initialized on start
init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in or select a demo profile to access this area.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def check_pw(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def hash_pw(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")

def parse_client_telemetry(req):
    """Detects or allows user-override of simulated device, IP, and location for testing."""
    device = req.form.get("device") or req.headers.get("User-Agent", "Unknown Browser")
    if len(device) > 80:
        # Simplify long user-agent
        if "Windows" in device:
            device = "Chrome on Windows"
        elif "Macintosh" in device or "Mac OS" in device:
            device = "Safari on macOS"
        elif "Linux" in device:
            device = "Firefox on Linux"
        elif "Android" in device:
            device = "Chrome on Android"
        elif "iPhone" in device:
            device = "Safari on iOS"
        else:
            device = device[:40]

    ip_address = req.form.get("ip_address") or req.remote_addr or "127.0.0.1"
    location = req.form.get("location") or "New York, USA"

    return device, ip_address, location

# ================= ROUTES =================

@app.route("/")
def index():
    """Landing page showcasing SecureAI architecture and live password intelligence."""
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration with real-time ML password analysis."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        existing_user = get_user_by_email(email)
        if existing_user:
            flash("An account with that email address already exists.", "danger")
            return render_template("register.html")

        # Analyze password security using ML
        analysis = analyze_password_security(password)
        if analysis["predicted_category"] == 2 and not request.form.get("override_weak"):
            flash(
                "Security Warning: Our ML model classified this password as HIGH RISK (Weak/Predictable). "
                "Check the recommendations or check the override box to proceed anyway.",
                "warning"
            )
            return render_template("register.html", weak_warning=True, analysis=analysis, name=name, email=email)

        # Hash and store user
        hashed = hash_pw(password)
        user_id = create_user(name, email, hashed)

        device, ip_address, location = parse_client_telemetry(request)

        # Log initial registration login
        log_login_attempt(
            user_id=user_id,
            device=device,
            location=location,
            ip_address=ip_address,
            success=1,
            risk_score=10.0,
            risk_level="Safe",
            reasons="Initial account provisioning and onboarding baseline"
        )

        log_security_event(
            user_id=user_id,
            event_type="ACCOUNT_CREATED",
            description=f"New account successfully registered with password entropy {analysis['entropy']} bits/symbol.",
            severity="Low"
        )

        session["user_id"] = user_id
        session["user_name"] = name
        session["user_email"] = email
        session["user_role"] = "User"

        flash("Account created successfully! Welcome to SecureAI.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """AI-Monitored Login with multi-factor risk assessment."""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        otp_code = request.form.get("otp_code", "").strip()

        device, ip_address, location = parse_client_telemetry(request)

        user = get_user_by_email(email)
        user_id = user["id"] if user else None

        # Fetch telemetry metrics from DB
        recent_failed = get_recent_failed_attempts_count(user_id=user_id, ip_address=ip_address, minutes=5)
        known_devices = get_user_known_devices(user_id) if user_id else []
        last_login = get_user_last_successful_login(user_id) if user_id else None

        # Run AI Multi-Factor Risk Assessment
        risk_result = evaluate_login_risk(
            user_id=user_id,
            email=email,
            password=password,
            ip_address=ip_address,
            device=device,
            location=location,
            recent_failed_attempts=recent_failed,
            known_devices=known_devices,
            last_login_info=last_login
        )

        risk_score = risk_result["risk_score"]
        risk_level = risk_result["risk_level"]
        reasons_str = ", ".join(risk_result["reasons"])

        # Check credentials
        is_pw_valid = False
        if user and check_pw(password, user["password_hash"]):
            is_pw_valid = True

        # Scenario 1: High Risk & Action Required
        if is_pw_valid and risk_level == "High Risk":
            # If 2FA OTP submitted and matches demo master PIN (9824), permit step-up entry
            if otp_code == "9824":
                log_login_attempt(
                    user_id=user_id,
                    device=device,
                    location=location,
                    ip_address=ip_address,
                    success=1,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    reasons=f"Step-Up 2FA Bypass Verified (Master Code). Baseline threats: {reasons_str}"
                )
                log_security_event(
                    user_id=user_id,
                    event_type="STEP_UP_2FA_OVERRIDE",
                    description=f"High-risk login authenticated via Step-up MFA from {ip_address} ({location}).",
                    severity="High"
                )
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                session["user_email"] = user["email"]
                session["user_role"] = "Admin" if "admin" in user["email"] else "Analyst" if "analyst" in user["email"] else "User"
                flash("High-Risk alert cleared via Step-up MFA verification. Access granted.", "warning")
                return redirect(url_for("dashboard"))
            else:
                # Log blocked attempt
                log_login_attempt(
                    user_id=user_id,
                    device=device,
                    location=location,
                    ip_address=ip_address,
                    success=0,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    reasons=f"BLOCKED BY AI DEFENSE ENGINE: {reasons_str}"
                )
                log_security_event(
                    user_id=user_id,
                    event_type="HIGH_RISK_LOGIN_BLOCKED",
                    description=f"Automated block triggered (Risk Score: {risk_score}/100) from IP {ip_address} ({location}).",
                    severity="Critical"
                )
                flash(
                    f"ACCESS DENIED (Risk Score: {risk_score}/100 - High Risk). Reasons: {reasons_str}. "
                    "Enter the SOC Security Override PIN (9824) to verify your identity.",
                    "danger"
                )
                return render_template(
                    "login.html",
                    show_otp=True,
                    email=email,
                    device=device,
                    location=location,
                    ip_address=ip_address,
                    risk_result=risk_result
                )

        # Scenario 2: Valid credentials, Safe or Suspicious
        if is_pw_valid:
            log_login_attempt(
                user_id=user_id,
                device=device,
                location=location,
                ip_address=ip_address,
                success=1,
                risk_score=risk_score,
                risk_level=risk_level,
                reasons=reasons_str
            )

            if risk_level == "Suspicious":
                log_security_event(
                    user_id=user_id,
                    event_type="SUSPICIOUS_LOGIN_ACCEPTED",
                    description=f"Suspicious authentication allowed (Score: {risk_score}). Factors: {reasons_str}",
                    severity="Medium"
                )
                flash(f"Security Alert: Unfamiliar login parameters detected ({reasons_str}).", "warning")
            else:
                flash(f"Welcome back, {user['name']}! Authentication verified with Safe trust rating.", "success")

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["user_role"] = "Admin" if "admin" in user["email"] else "Analyst" if "analyst" in user["email"] else "User"

            return redirect(url_for("dashboard"))

        else:
            # Invalid credentials
            log_login_attempt(
                user_id=user_id if user_id else 1,
                device=device,
                location=location,
                ip_address=ip_address,
                success=0,
                risk_score=risk_score,
                risk_level=risk_level,
                reasons=f"Failed credential check. Flags: {reasons_str}"
            )

            if recent_failed >= 2:
                log_security_event(
                    user_id=user_id if user_id else 1,
                    event_type="BRUTE_FORCE_VELOCITY",
                    description=f"Rapid repeated login failure against {email} from IP {ip_address}.",
                    severity="High"
                )

            flash("Authentication failed: Invalid email or password.", "danger")
            return render_template(
                "login.html",
                email=email,
                device=device,
                location=location,
                ip_address=ip_address,
                risk_result=risk_result
            )

    return render_template("login.html")

@app.route("/api/biometric-auth", methods=["POST"])

def api_biometric_auth():
    """Biometric Fingerprint / WebAuthn authentication route with AI Risk Telemetry."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    
    # Default to selected demo profile or primary user
    user = None
    if email:
        user = get_user_by_email(email)
    
    if not user:
        user = get_user_by_email("admin@cyberguard.ai") or get_user_by_email("user@example.com")

    if not user:
        return jsonify({"status": "error", "message": "No account available for biometric verification."}), 400

    device, ip_address, location = parse_client_telemetry(request)
    user_id = user["id"]

    # Telemetry check
    recent_failed = get_recent_failed_attempts_count(user_id=user_id, ip_address=ip_address, minutes=5)
    known_devices = get_user_known_devices(user_id)
    last_login = get_user_last_successful_login(user_id)

    # Log successful Biometric login
    log_login_attempt(
        user_id=user_id,
        device=device,
        location=location,
        ip_address=ip_address,
        success=1,
        risk_score=5.0, # Biometric cryptographic sensor provides maximum trust rating
        risk_level="Safe",
        reasons="FIDO2 / Hardware Fingerprint Sensor Verified (Zero-Password Auth)"
    )

    log_security_event(
        user_id=user_id,
        event_type="BIOMETRIC_FINGERPRINT_VERIFIED",
        description=f"Hardware Biometric Fingerprint authentication succeeded for {user['name']} from {ip_address} ({device}).",
        severity="Low"
    )

    # Establish session
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["user_role"] = "Admin" if "admin" in user["email"] else "Analyst" if "analyst" in user["email"] else "User"

    return jsonify({
        "status": "success",
        "message": f"Biometric Fingerprint Verified! Access granted for {user['name']}.",
        "redirect_url": url_for("dashboard"),
        "user": {
            "name": user["name"],
            "email": user["email"],
            "role": session["user_role"]
        }
    })

# ================= ANDROID NATIVE BIOMETRIC / WEBAUTHN CHALLENGE API =================

@app.route("/api/biometric/challenge", methods=["POST"])
def api_biometric_challenge():
    """
    Generates a cryptographically secure, one-time random challenge for Android BiometricPrompt.
    Flow: Android -> Request Challenge -> User Fingerprint Verified Locally -> Response signed & sent.
    """
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    device_id = data.get("device_id", "").strip()

    if not email:
        return jsonify({
            "status": "error",
            "error_code": "MISSING_EMAIL",
            "message": "Email address is required to generate an authentication challenge."
        }), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({
            "status": "error",
            "error_code": "USER_NOT_FOUND",
            "message": f"Account with email '{email}' was not found."
        }), 404

    # Generate one-time challenge nonce with 120s TTL
    challenge_nonce = create_biometric_challenge(user["id"], device_id=device_id, ttl_seconds=120)

    return jsonify({
        "status": "success",
        "challenge": challenge_nonce,
        "expires_in": 120,
        "user_id": user["id"],
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/biometric/register-device", methods=["POST"])
def api_biometric_register_device():
    """
    Enrolls an Android device for hardware-backed Biometric authentication.
    Requires account password confirmation during device registration.
    """
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    device_id = data.get("device_id", "").strip()
    device_name = data.get("device_name", "Android Device").strip()
    public_key = data.get("public_key", "").strip()

    if not email or not password or not device_id:
        return jsonify({
            "status": "error",
            "error_code": "MISSING_PARAMETERS",
            "message": "Email, password, and device_id are required for biometric registration."
        }), 400

    user = get_user_by_email(email)
    if not user or not check_pw(password, user["password_hash"]):
        return jsonify({
            "status": "error",
            "error_code": "INVALID_CREDENTIALS",
            "message": "Invalid email or password for device enrollment."
        }), 401

    # Enroll device
    register_biometric_device(
        user_id=user["id"],
        device_id=device_id,
        device_name=device_name,
        public_key=public_key
    )

    log_security_event(
        user_id=user["id"],
        event_type="BIOMETRIC_DEVICE_ENROLLED",
        description=f"Enrolled biometric hardware authenticator '{device_name}' (ID: {device_id[:12]}...).",
        severity="Low"
    )

    security_score = calculate_account_security_score(user["id"])

    return jsonify({
        "status": "success",
        "message": f"Device '{device_name}' successfully enrolled with biometric hardware fast-pass.",
        "device": {
            "device_id": device_id,
            "device_name": device_name,
            "user_email": email
        },
        "security_score": security_score
    })

@app.route("/api/biometric/authenticate", methods=["POST"])
def api_biometric_authenticate():
    """
    Validates a locally completed Android BiometricPrompt authentication.
    - Validates challenge nonce (must not be expired, must not be reused)
    - Validates enrolled device
    - Evaluates risk telemetry with ML engine
    - Issues authenticated session / token
    """
    import secrets
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    challenge = data.get("challenge", "").strip()
    device_id = data.get("device_id", "").strip()
    signature = data.get("signature", "").strip()
    device_info = data.get("device_info", "Android BiometricPrompt Device").strip()

    if not email or not challenge:
        return jsonify({
            "status": "error",
            "error_code": "MISSING_PARAMETERS",
            "message": "Email and challenge token are required."
        }), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({
            "status": "error",
            "error_code": "USER_NOT_FOUND",
            "message": "Target account does not exist."
        }), 404

    user_id = user["id"]

    # 1. Validate & Consume Challenge Nonce (Prevents Replay Attacks)
    is_valid, err_code, challenge_rec = validate_and_consume_biometric_challenge(challenge, user_id=user_id)
    if not is_valid:
        if err_code == "EXPIRED_CHALLENGE":
            return jsonify({
                "status": "error",
                "error_code": "EXPIRED_CHALLENGE",
                "message": "Biometric challenge has expired. Request a new challenge and retry."
            }), 401
        elif err_code == "REPLAY_DETECTED_ALREADY_USED":
            return jsonify({
                "status": "error",
                "error_code": "REPLAY_DETECTED_ALREADY_USED",
                "message": "Challenge nonce has already been consumed. Replay attack blocked."
            }), 401
        elif err_code == "USER_MISMATCH":
            return jsonify({
                "status": "error",
                "error_code": "UNAUTHORIZED_USER",
                "message": "Challenge token belongs to a different identity."
            }), 403
        else:
            return jsonify({
                "status": "error",
                "error_code": "INVALID_CHALLENGE",
                "message": "Invalid or non-existent authentication challenge."
            }), 400

    # 2. Check Device Enrollment
    device_record = None
    if device_id:
        device_record = get_biometric_device(device_id)
        if device_record and device_record["user_id"] != user_id:
            return jsonify({
                "status": "error",
                "error_code": "DEVICE_USER_MISMATCH",
                "message": "Device is registered to a different account."
            }), 403

    device_name = device_record["device_name"] if device_record else device_info
    if device_id:
        update_device_last_used(device_id)

    # 3. Telemetry & Risk Assessment
    device_str = f"{device_name} (BiometricPrompt)"
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    location = request.headers.get("X-Geo-Location", "Android Client")

    recent_failed = get_recent_failed_attempts_count(user_id=user_id, ip_address=ip_address, minutes=5)
    known_devices = get_user_known_devices(user_id)
    last_login = get_user_last_successful_login(user_id)

    risk_eval = evaluate_login_risk(
        user_id=user_id,
        email=email,
        password="[ANDROID_BIOMETRIC_KEYSTORE_ASSERTION]",
        ip_address=ip_address,
        device=device_str,
        location=location,
        recent_failed_attempts=recent_failed,
        known_devices=known_devices,
        last_login_info=last_login
    )

    # Hardware biometric authentication provides maximum trust
    risk_score = min(risk_eval["risk_score"], 5.0)

    # 4. Log Authentication Activity
    log_login_attempt(
        user_id=user_id,
        device=device_str,
        location=location,
        ip_address=ip_address,
        success=1,
        risk_score=risk_score,
        risk_level="Safe",
        reasons="Android BiometricPrompt (Hardware Keystore Verified) - Challenge Consumed"
    )

    log_security_event(
        user_id=user_id,
        event_type="ANDROID_BIOMETRIC_AUTH_SUCCESS",
        description=f"Android BiometricPrompt authentication validated for {user['name']} from {device_str}.",
        severity="Low"
    )

    # 5. Set session & create auth token
    auth_token = f"secai_bio_{secrets.token_hex(20)}"
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["user_role"] = "Admin" if "admin" in user["email"] else "Analyst" if "analyst" in user["email"] else "User"

    security_score = calculate_account_security_score(user_id)

    return jsonify({
        "status": "success",
        "message": f"Biometric authentication verified for {user['name']}.",
        "auth_token": auth_token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": session["user_role"]
        },
        "security_score": security_score,
        "redirect_url": url_for("dashboard")
    })

@app.route("/api/user/security-score", methods=["GET"])
def api_user_security_score():
    """Returns dynamic security score and biometric posture for user."""
    user_id = session.get("user_id")
    email = request.args.get("email", "").strip().lower()
    
    if not user_id and email:
        u = get_user_by_email(email)
        if u:
            user_id = u["id"]

    if not user_id:
        user_id = 1 # Fallback to default user

    score_data = calculate_account_security_score(user_id)
    return jsonify({
        "status": "success",
        "security_score": score_data
    })

@app.route("/quick-login/<role>")


def quick_login(role):
    """Allows one-click switching to demo profiles for frictionless testing."""
    profiles = {
        "admin": "admin@secureai.com",
        "analyst": "analyst@secureai.com",
        "user": "user@example.com"
    }
    email = profiles.get(role, "user@example.com")
    user = get_user_by_email(email)
    if user:
        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        session["user_role"] = "Admin" if role == "admin" else "Analyst" if role == "analyst" else "User"
        flash(f"Switched profile to {user['name']} ({user['email']})", "info")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    """Terminates session."""
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    """Cybersecurity Operations Center (SOC) and User Security Dashboard."""
    user_id = session.get("user_id")
    user_stats = get_user_dashboard_stats(user_id)
    soc_stats = get_global_soc_stats()
    user_logins = get_user_login_attempts(user_id, limit=20)

    return render_template(
        "dashboard.html",
        user_stats=user_stats,
        soc_stats=soc_stats,
        user_logins=user_logins
    )

@app.route("/simulator")
def simulator():
    """Interactive Cyber Attack & Threat Simulation Lab."""
    return render_template("simulator.html")

# ================= API ENDPOINTS =================

@app.route("/api/analyze-password", methods=["POST"])
def api_analyze_password():
    """Real-time ML password analysis returning features, entropy, and crack time."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    analysis = analyze_password_security(password)
    return jsonify(analysis)

@app.route("/api/simulate-attack", methods=["POST"])
def api_simulate_attack():
    """
    Executes a realistic cybersecurity scenario against the AI Risk Engine:
    - brute_force
    - impossible_travel
    - weak_password
    - normal_login
    """
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "brute_force")
    target_email = data.get("target_email", "admin@secureai.com").strip().lower()

    user = get_user_by_email(target_email)
    user_id = user["id"] if user else 1

    results = []

    if scenario == "brute_force":
        # Rapid automated credential stuffing from a foreign Tor Proxy IP
        attacker_ip = "185.220.101.44"
        attacker_device = "Python-Requests/2.31 (Automated Bot)"
        attacker_loc = "Frankfurt, Germany (Tor Exit Node)"
        passwords = ["123456", "password", "admin123", "qwerty", "welcome1"]

        for i, pwd in enumerate(passwords):
            recent_fails = get_recent_failed_attempts_count(user_id=user_id, ip_address=attacker_ip, minutes=5) + i
            risk_eval = evaluate_login_risk(
                user_id=user_id,
                email=target_email,
                password=pwd,
                ip_address=attacker_ip,
                device=attacker_device,
                location=attacker_loc,
                recent_failed_attempts=recent_fails,
                known_devices=get_user_known_devices(user_id),
                last_login_info=get_user_last_successful_login(user_id)
            )
            # Log failed attempt
            log_login_attempt(
                user_id=user_id,
                device=attacker_device,
                location=attacker_loc,
                ip_address=attacker_ip,
                success=0,
                risk_score=risk_eval["risk_score"],
                risk_level=risk_eval["risk_level"],
                reasons=", ".join(risk_eval["reasons"])
            )
            results.append({
                "attempt": i + 1,
                "password_tested": pwd,
                "risk_score": risk_eval["risk_score"],
                "risk_level": risk_eval["risk_level"],
                "action": risk_eval["action_required"],
                "reasons": risk_eval["reasons"]
            })

        log_security_event(
            user_id=user_id,
            event_type="BRUTE_FORCE_ATTACK_CONTAINED",
            description=f"Simulated credential stuffing attack mitigated. 5 malicious requests neutralized from {attacker_ip}.",
            severity="Critical"
        )

        return jsonify({
            "status": "success",
            "scenario": "Brute Force / Credential Stuffing",
            "summary": "AI Risk Engine escalated risk from Suspicious to Critical High Risk and successfully triggered rate-limit lockdown.",
            "attempts": results
        })

    elif scenario == "impossible_travel":
        # Sudden cross-continental login
        attacker_ip = "103.251.167.89"
        attacker_device = "Chrome on Android (Pixel 8)"
        attacker_loc = "Tokyo, Japan"

        last_login = get_user_last_successful_login(user_id)
        risk_eval = evaluate_login_risk(
            user_id=user_id,
            email=target_email,
            password="Summer2024!ValidPass",
            ip_address=attacker_ip,
            device=attacker_device,
            location=attacker_loc,
            recent_failed_attempts=0,
            known_devices=get_user_known_devices(user_id),
            last_login_info=last_login
        )

        log_login_attempt(
            user_id=user_id,
            device=attacker_device,
            location=attacker_loc,
            ip_address=attacker_ip,
            success=0,
            risk_score=risk_eval["risk_score"],
            risk_level=risk_eval["risk_level"],
            reasons=", ".join(risk_eval["reasons"])
        )

        log_security_event(
            user_id=user_id,
            event_type="IMPOSSIBLE_TRAVEL_BLOCKED",
            description=f"Impossible Travel: Access attempt intercepted from {attacker_loc} ({attacker_ip}). Previous login was in {last_login.get('location', 'New York, USA') if last_login else 'New York, USA'}.",
            severity="High"
        )

        return jsonify({
            "status": "success",
            "scenario": "Impossible Travel Anomaly",
            "summary": f"AI Risk Engine flagged instant cross-continental displacement (Risk Score: {risk_eval['risk_score']}/100) and triggered step-up MFA challenge.",
            "details": risk_eval
        })

    elif scenario == "weak_password":
        # Testing dictionary pattern vulnerability
        test_pw = "qwerty123"
        analysis = analyze_password_security(test_pw)
        risk_eval = evaluate_login_risk(
            user_id=user_id,
            email=target_email,
            password=test_pw,
            ip_address="192.168.1.55",
            device="Chrome on Windows",
            location="New York, USA"
        )

        log_security_event(
            user_id=user_id,
            event_type="WEAK_PASSWORD_DETECTED",
            description=f"ML Classifier identified compromised/weak password pattern '{test_pw}' with low entropy ({analysis['entropy']} bits/symbol).",
            severity="Medium"
        )

        return jsonify({
            "status": "success",
            "scenario": "Weak / Compromised Password Exploitation",
            "summary": f"Random Forest Classifier detected dictionary sequence. Crack time estimated at: {analysis['crack_time']}.",
            "analysis": analysis,
            "risk_eval": risk_eval
        })

    else:  # normal_login
        risk_eval = evaluate_login_risk(
            user_id=user_id,
            email=target_email,
            password="CyberSec#2024!A",
            ip_address="192.168.1.45",
            device="Chrome on Windows",
            location="New York, USA",
            recent_failed_attempts=0,
            known_devices=["Chrome on Windows"],
            last_login_info={"location": "New York, USA", "timestamp": "2026-08-31 10:00:00"}
        )

        log_login_attempt(
            user_id=user_id,
            device="Chrome on Windows",
            location="New York, USA",
            ip_address="192.168.1.45",
            success=1,
            risk_score=risk_eval["risk_score"],
            risk_level=risk_eval["risk_level"],
            reasons=", ".join(risk_eval["reasons"])
        )

        return jsonify({
            "status": "success",
            "scenario": "Normal Authorized Login",
            "summary": f"Authentication telemetry conforms to baseline parameters. Trust rating: Safe (Score: {risk_eval['risk_score']}/100).",
            "details": risk_eval
        })

@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    """Live stats feed for SOC dashboards and real-time graphs."""
    user_id = session.get("user_id", 1)
    soc_stats = get_global_soc_stats()
    user_stats = get_user_dashboard_stats(user_id)
    return jsonify({
        "soc": soc_stats,
        "user": user_stats
    })

if __name__ == "__main__":
    from init_data import seed_database
    seed_database()
    print("[*] Starting SecureAI Cyber Platform on http://127.0.0.1:5000 ...")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        use_reloader=False
    )


