import os
import re
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

app = Flask(__name__)
# Enable CORS so the frontend can communicate with the backend
CORS(app)

gemini_api_key: str = os.getenv("GEMINI_API_KEY")

# MySQL Connection and Auto-Setup
def get_db_connection():
    host = os.getenv("MYSQL_HOST", "localhost")
    user = os.getenv("MYSQL_USER", "root")
    password = os.getenv("MYSQL_PASSWORD", "")
    db = os.getenv("MYSQL_DATABASE", "safejob")
    try:
        print(f"DEBUG: Attempting connection to {host} as {user} with password: {'***' if password else 'NONE'}")
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=db
        )
        return conn
    except Exception as e:
        print(f"MySQL Connection Error: {e}")
        return None

try:
    # First, connect to the MySQL setup (without specifying a database)
    initial_password = os.getenv("MYSQL_PASSWORD", "")
    db_setup = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=initial_password
    )
    cursor = db_setup.cursor()
    # Create the database automatically if it doesn't exist
    db_name = os.getenv("MYSQL_DATABASE", "safejob")
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    db_setup.commit()
    cursor.close()
    db_setup.close()

    # Now, connect to the specific database to setup the table
    setup_conn = get_db_connection()
    if setup_conn:
        cursor = setup_conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS job_scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                job_text TEXT NOT NULL,
                result VARCHAR(50) NOT NULL,
                risk_score INT NOT NULL,
                flagged_keywords TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT
            )
        """)
        setup_conn.commit()
        # Ensure new columns exist if the table was created before this update
        try:
            cursor.execute("ALTER TABLE job_scans ADD COLUMN ip_address VARCHAR(45)")
            cursor.execute("ALTER TABLE job_scans ADD COLUMN user_agent TEXT")
            setup_conn.commit()
        except Exception:
            pass
        cursor.close()
        setup_conn.close()
        print("MySQL database and table perfectly verified/created!")
except Exception as e:
    print(f"Warning: Failed to setup MySQL database: {e}")

if gemini_api_key and gemini_api_key != "your_gemini_api_key_here":
    genai.configure(api_key=gemini_api_key)

def analyze_with_gemini(text):
    if not gemini_api_key or gemini_api_key == "your_gemini_api_key_here":
        return None
        
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"""
        You are an expert fraud detection AI specialized in spotting fake job offers, especially those targeting vulnerable job seekers.
        Analyze the following text and determine if it's a scam or a genuine job opportunity.
        
        Respond ONLY with a valid JSON document in exactly the following format. Ensure there is no markdown formatting, no backticks, just raw JSON:
        {{
            "risk_score": <int between 0 and 100>,
            "risk_level": "<low|medium|high>",
            "classification": "<genuine|fake>",
            "flagged_keywords": ["<keyword or suspicious phrase 1>", "<phrase 2>"]
        }}
        
        Job Text:
        {text}
        """
        response = model.generate_content(prompt)
        result_text = response.text.replace('```json', '').replace('```', '').strip()
        data = json.loads(result_text)
        
        return {
            "risk_score": int(data.get("risk_score", 50)),
            "risk_level": str(data.get("risk_level", "medium")).lower(),
            "classification": str(data.get("classification", "fake")).lower(),
            "flagged_keywords": list(data.get("flagged_keywords", []))
        }
    except Exception as e:
        print(f"Gemini API error: {e}")
        return None

# Weighted scam patterns (50+ keywords/phrases categorized by severity)
STRICT_SCAM_PATTERNS = {
    # HIGH RISK (Weight: 30) - Almost certainly a scam
    "high": [
        "registration fee", "training fee", "security deposit", "processing fee",
        "refundable fee", "send photo", "send your photo", "attractive females",
        "easy money", "wire transfer", "pay upfront", "bank details", 
        "pay to work", "pay first", "pay ₹", "pay rs", "deposit required",
        "100% guaranteed income", "guaranteed cash", "earn lakhs", 
        "no interview", "get rich quick", "pyramid scheme", "investment required"
    ],
    # MEDIUM RISK (Weight: 15) - Very suspicious, often used in scams
    "medium": [
        "urgent hiring", "immediate joining", "limited seats", "act now",
        "offer expires today", "no experience required", "no experience needed",
        "no qualifications needed", "anyone can do this", "data entry",
        "form filling", "copy paste job", "sms sending job", "captcha typing",
        "whatsapp only", "no calls please", "message on whatsapp",
        "work from home and earn", "be your own boss", "network marketing"
    ],
    # LOW RISK (Weight: 5) - Common but can appear in legitimate jobs
    "low": [
        "work from home", "remote work", "daily payment", "weekly payout",
        "flexible hours", "part time income", "extra income", "earn online",
        "hiring freshers", "entry level"
    ]
}

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Empty input provided"}), 400
    
    text = data.get('text', '')
    if not text.strip():
        return jsonify({"error": "Job description cannot be empty"}), 400

    # Try to analyze with Gemini API first
    gemini_result = analyze_with_gemini(text)
    
    if gemini_result:
        risk_score = gemini_result["risk_score"]
        risk_level = gemini_result["risk_level"]
        classification = gemini_result["classification"]
        flagged_keywords = gemini_result["flagged_keywords"]
    else:
        # Fallback to local weighted pattern detection if Gemini key is missing
        text_lower = text.lower()
        flagged_keywords = []
        risk_score = 0
        
        # Check against all pattern lists
        for level, patterns in STRICT_SCAM_PATTERNS.items():
            for pattern in patterns:
                # We use simple string matching here; regex could be used for advanced matching
                if pattern in text_lower:
                    flagged_keywords.append(pattern)
                    # Add weights based on severity
                    if level == "high":
                        risk_score += 30
                    elif level == "medium":
                        risk_score += 15
                    elif level == "low":
                        risk_score += 5
                        
        # Provide a base risk to start
        if risk_score > 0 and risk_score < 10:
            risk_score += 5 
            
        # Cap score at 100
        if risk_score > 100:
            risk_score = 100
        
        # Very low risk if nothing is flagged
        if len(flagged_keywords) == 0:
            risk_score = 5 
        
        # Determine risk level based on score
        if risk_score < 30:
            risk_level = "low"
        elif risk_score < 60:
            risk_level = "medium"
        else:
            risk_level = "high"
            
        classification = "fake" if risk_score >= 31 else "genuine"
    
    # Capture user data
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Database insertion (MySQL)
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            sql = "INSERT INTO job_scans (job_text, result, risk_score, flagged_keywords, ip_address, user_agent) VALUES (%s, %s, %s, %s, %s, %s)"
            val = (text, classification, risk_score, json.dumps(flagged_keywords), ip_address, user_agent)
            cursor.execute(sql, val)
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error inserting into MySQL: {e}")
            return jsonify({"error": f"MYSQL INSERT ERROR: {str(e)}"}), 500
    else:
        return jsonify({"error": "MYSQL DATABASE NOT CONNECTED! Please restart the python terminal."}), 500

    return jsonify({
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "flagged_keywords": flagged_keywords
    }), 200

# ==========================================
# ADMIN PANEL: API ENDPOINTS
# ==========================================
@app.route('/api/admin/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database not connected"}), 500
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as total FROM job_scans")
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as fake FROM job_scans WHERE result = 'fake'")
        fake = cursor.fetchone()['fake']
        
        cursor.execute("SELECT COUNT(*) as genuine FROM job_scans WHERE result = 'genuine'")
        genuine = cursor.fetchone()['genuine']
        cursor.close()
        conn.close()
        
        return jsonify({"total": total, "fake": fake, "genuine": genuine}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/scans', methods=['GET'])
def get_scans():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database not connected"}), 500
    try:
        cursor = conn.cursor(dictionary=True)
        # Fetch the latest 50 scans, including their user IP and scores!
        cursor.execute("SELECT id, created_at, result, risk_score, ip_address, flagged_keywords, LEFT(job_text, 150) as job_text_excerpt FROM job_scans ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Convert datetime to string so JSON doesn't break
        for row in rows:
            if row.get('created_at'):
                row['created_at'] = str(row['created_at'])
                
        return jsonify(rows), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/delete/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database not connected"}), 500
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM job_scans WHERE id = %s", (scan_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": f"Scan #{scan_id} deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
