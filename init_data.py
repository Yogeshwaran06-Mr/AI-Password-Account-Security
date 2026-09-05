import os
import sys
import bcrypt
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from models.db_model import init_db, get_db_connection, create_user, log_login_attempt, log_security_event, get_user_by_email

def hash_pw(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def seed_database():
    print("[*] Initializing SQLite database schema...")
    init_db()

    conn = get_db_connection()
    # Check if already seeded
    user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    conn.close()

    if user_count > 0:
        print("[!] Database already populated. Skipping user creation.")
    else:
        print("[*] Creating demo cybersecurity accounts...")
        # 1. Admin account
        admin_id = create_user(
            name="Security Admin",
            email="admin@secureai.com",
            password_hash=hash_pw("CyberSec#2024!A")
        )

        # 2. Analyst account
        analyst_id = create_user(
            name="SOC Analyst",
            email="analyst@secureai.com",
            password_hash=hash_pw("VortexShield#99")
        )

        # 3. Regular Demo user
        user_id = create_user(
            name="Alex Mercer",
            email="user@example.com",
            password_hash=hash_pw("Summer2024!Pass")
        )

        print(f"[+] Created users: admin (ID {admin_id}), analyst (ID {analyst_id}), user (ID {user_id})")

        # Seed historical login attempts
        print("[*] Generating realistic telemetry and login records...")
        now = datetime.utcnow()

        login_history = [
            # Normal user logins
            (user_id, "Chrome on Windows", "New York, USA", "192.168.1.45", 1, 12.0, "Safe", "Normal baseline authentication telemetry", now - timedelta(days=2, hours=4)),
            (user_id, "Chrome on Windows", "New York, USA", "192.168.1.45", 1, 15.0, "Safe", "Normal baseline authentication telemetry", now - timedelta(days=1, hours=8)),
            (user_id, "Safari on iOS", "New York, USA", "192.168.1.112", 1, 32.0, "Safe", "Unrecognized device/browser fingerprint: 'Safari on iOS'", now - timedelta(hours=14)),
            
            # Suspicious login from unexpected browser & location
            (user_id, "Firefox on Linux", "London, UK", "82.165.197.1", 1, 55.0, "Suspicious", "Unrecognized device/browser fingerprint, New geographic origin: 'London, UK'", now - timedelta(hours=6)),
            
            # Brute force attack against admin
            (admin_id, "Python-Requests/2.31", "Frankfurt, Germany (Tor Node)", "185.220.101.5", 0, 85.0, "High Risk", "High-Risk/Weak Password identified by ML Classifier, Suspicious IP / Proxy origin detected", now - timedelta(hours=3, minutes=15)),
            (admin_id, "Python-Requests/2.31", "Frankfurt, Germany (Tor Node)", "185.220.101.5", 0, 90.0, "High Risk", "Elevated velocity: 2 recent failed login attempts, Suspicious IP / Proxy origin", now - timedelta(hours=3, minutes=14)),
            (admin_id, "Python-Requests/2.31", "Frankfurt, Germany (Tor Node)", "185.220.101.5", 0, 95.0, "High Risk", "Critical velocity: 3 failed attempts in the last 5 minutes (Brute-Force suspected)", now - timedelta(hours=3, minutes=13)),
            (admin_id, "Python-Requests/2.31", "Frankfurt, Germany (Tor Node)", "185.220.101.5", 0, 98.0, "High Risk", "Automated attack blocked by Rate-Limiting Policy", now - timedelta(hours=3, minutes=12)),
            
            # Legitimate admin login
            (admin_id, "Chrome on macOS", "San Francisco, USA", "198.51.100.22", 1, 8.0, "Safe", "Hardware token verified, strong password entropy", now - timedelta(hours=2)),
            
            # Impossible travel against user account
            (user_id, "Chrome on Android", "Tokyo, Japan", "103.251.167.22", 0, 92.0, "High Risk", "Impossible Travel: Location shifted from London, UK to Tokyo, Japan within 15 minutes", now - timedelta(minutes=45)),
            
            # Recent analyst safe login
            (analyst_id, "Edge on Windows", "Austin, USA", "172.56.21.90", 1, 14.0, "Safe", "Normal baseline authentication telemetry", now - timedelta(minutes=20))
        ]

        for uid, dev, loc, ip, succ, score, lvl, rsn, ts in login_history:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO login_attempts (user_id, device, location, ip_address, success, risk_score, risk_level, reasons, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (uid, dev, loc, ip, succ, score, lvl, rsn, ts.strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            conn.close()

        # Seed Security Alerts
        print("[*] Generating SOC threat events and alerts...")
        events = [
            (admin_id, "BRUTE_FORCE_PREVENTED", "Active brute force attack mitigated. 4 automated attempts blocked from IP 185.220.101.5 (Frankfurt).", "Critical"),
            (user_id, "IMPOSSIBLE_TRAVEL_FLAG", "Account access attempt blocked: impossible travel detected between London and Tokyo in 15 minutes.", "High"),
            (user_id, "SUSPICIOUS_LOGIN_CHALLENGED", "Step-up 2FA verification triggered for unfamiliar Linux device from London.", "Medium"),
            (admin_id, "SOC_AUDIT_BASELINE", "Weekly identity security policy and ML anomaly thresholds updated.", "Low")
        ]

        for uid, ev_type, desc, sev in events:
            log_security_event(uid, ev_type, desc, sev)

        # Seed enrolled demo biometric devices
        from models.db_model import register_biometric_device
        register_biometric_device(user_id, "android_demo_pixel8_id", "Google Pixel 8 Pro (Android 14)", "demo_pubkey_keystore_assertion")
        register_biometric_device(admin_id, "android_demo_samsung_s24", "Samsung Galaxy S24 Ultra", "demo_pubkey_keystore_assertion")

        print("[+] Seed completed successfully!")


if __name__ == "__main__":
    seed_database()
