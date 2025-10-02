import psycopg2
from flask import Flask, jsonify, request
import requests
from haversine import haversine, Unit
from datetime import datetime

# --- SUPABASE DATABASE DETAILS ---
DB_HOST = "db.actefjbrmcrvwghlsgls.supabase.co"
DB_PASS = "odHB9gpHtF4kehvs"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PORT = "5432"
# ---------------------------------

app = Flask(__name__)

def get_db_connection():
    conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, port=DB_PORT)
    return conn

def get_geo_from_ip(ip_address):
    """IP એડ્રેસ પરથી Latitude અને Longitude મેળવે છે."""
    try:
        # 127.0.0.1 એ લોકલ IP છે, તેનું લોકેશન નહીં મળે
        if ip_address == '127.0.0.1':
            return None, None # ટેસ્ટિંગ માટે
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=lat,lon")
        data = response.json()
        return data.get('lat'), data.get('lon')
    except:
        return None, None

@app.route('/')
def index():
    return "Fraud Detection Agent v2 is running."

@app.route('/score_event', methods=['POST'])
def score_event():
    try:
        event_data = request.json
        account_email = event_data.get('email')
        device_fingerprint = event_data.get('device_fingerprint')
        ip_address = event_data.get('ip_address')
        
        if not all([account_email, device_fingerprint, ip_address]):
            return jsonify({"status": "error", "message": "Missing required data"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # IDs મેળવો અથવા બનાવો (પહેલાની જેમ જ)
        cursor.execute("INSERT INTO accounts (email) VALUES (%s) ON CONFLICT (email) DO NOTHING RETURNING id;", (account_email,)); account_id = (cursor.fetchone() or cursor.execute("SELECT id FROM accounts WHERE email = %s;", (account_email,)), cursor.fetchone())[0][0]
        cursor.execute("INSERT INTO devices (fingerprint) VALUES (%s) ON CONFLICT (fingerprint) DO NOTHING RETURNING id;", (device_fingerprint,)); device_id = (cursor.fetchone() or cursor.execute("SELECT id FROM devices WHERE fingerprint = %s;", (device_fingerprint,)), cursor.fetchone())[0][0]
        cursor.execute("INSERT INTO ip_addresses (ip_address) VALUES (%s) ON CONFLICT (ip_address) DO NOTHING RETURNING id;", (ip_address,)); ip_id = (cursor.fetchone() or cursor.execute("SELECT id FROM ip_addresses WHERE ip_address = %s;", (ip_address,)), cursor.fetchone())[0][0]
        
        # --- Feature 1: Velocity Check ---
        cursor.execute("SELECT COUNT(*) FROM events WHERE account_id = %s AND created_at > NOW() - INTERVAL '5 minutes';", (account_id,))
        txn_count_5min = cursor.fetchone()[0]

        # --- Feature 2: Geo-location Check ---
        lat, lon = get_geo_from_ip(ip_address)
        impossible_travel = False
        if lat and lon:
            cursor.execute("SELECT latitude, longitude, created_at FROM events WHERE account_id = %s ORDER BY created_at DESC LIMIT 1;", (account_id,))
            last_event = cursor.fetchone()
            if last_event and last_event[0] and last_event[1]:
                last_lat, last_lon, last_time = last_event
                distance = haversine((last_lat, last_lon), (lat, lon), unit=Unit.KILOMETERS)
                time_diff_hours = (datetime.utcnow() - last_time.replace(tzinfo=None)).total_seconds() / 3600
                if time_diff_hours > 0:
                    speed = distance / time_diff_hours
                    if speed > 800: # 800 km/h કરતાં વધુ ઝડપ અશક્ય છે
                        impossible_travel = True

        # --- Feature 3: Graph Check (Shared Device) ---
        cursor.execute("SELECT COUNT(DISTINCT account_id) FROM events WHERE device_id = %s;", (device_id,))
        accounts_on_device = cursor.fetchone()[0]

        # --- Scoring Logic ---
        risk_score = 0.0
        reasons = []

        if txn_count_5min > 5:
            risk_score += 0.4
            reasons.append(f"High velocity: {txn_count_5min+1} transactions in 5 minutes.")
        if impossible_travel:
            risk_score += 0.5
            reasons.append("Impossible geo-location travel detected.")
        if accounts_on_device > 2:
            risk_score += 0.3
            reasons.append(f"Device shared by {accounts_on_device} accounts.")
        
        # Decision
        decision = "APPROVE"
        if risk_score >= 0.7:
            decision = "DECLINE"
        elif risk_score >= 0.4:
            decision = "REVIEW"

        # ઇવેન્ટને ડેટાબેઝમાં સાચવો
        cursor.execute(
            "INSERT INTO events (event_type, account_id, device_id, ip_id, status, risk_score, latitude, longitude) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
            ('login', account_id, device_id, ip_id, decision, risk_score, lat, lon)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "status": "success",
            "decision": decision,
            "risk_score": round(risk_score, 2),
            "reasons": reasons if reasons else ["Low risk."]
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    print(">>> Advanced Fraud Detection Server is running. Use an API client to test.")
    app.run(host='0.0.0.0', port=5000)