from flask import Flask, jsonify, render_template, request
import json
import re
import openai
import requests
from collections import Counter
from datetime import datetime

# --- CONFIGURATION ---

# 1. Groq API Key
try:
    # ---!!! REPLACE WITH YOUR GROQ KEY !!!---
    YOUR_GROQ_KEY = "YOUR_KEY_HERE" 
    
    if YOUR_GROQ_KEY == "gsk_YOUR_KEY_HERE":
        client = None
    else:
        client = openai.OpenAI(
            api_key=YOUR_GROQ_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
except Exception:
    client = None

# 2. AbuseIPDB API Key
# ---!!! REPLACE WITH YOUR ABUSEIPDB KEY !!!---
ABUSEIPDB_KEY = "YOUR_KEY_HERE" 


app = Flask(__name__)

# --- PAGE ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/investigation')
def investigation_page():
    return render_template('investigation.html')


# --- API ROUTES ---

@app.route('/api/alerts')
def get_alerts():
    """
    Main dashboard polling. Returns alerts + chart data.
    """
    alerts_data = []
    all_descriptions = []
    alerts_by_hour = {}
    
    try:
        with open('alerts.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                alert = json.loads(line)
                
                # Categorize
                level = alert.get('rule', {}).get('level', 0)
                category = 'Low'
                if level >= 10: category = 'High'
                elif level >= 7: category = 'Medium'
                alert['category'] = category
                
                alerts_data.append(alert)
                all_descriptions.append(alert.get('rule', {}).get('description', 'Unknown'))
                
                # Time series logic
                timestamp_str = alert.get('timestamp')
                if timestamp_str:
                    try:
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        hour_key = dt.strftime('%Y-%m-%d %H:00') 
                        alerts_by_hour[hour_key] = alerts_by_hour.get(hour_key, 0) + 1
                    except ValueError: pass
    except FileNotFoundError:
        return jsonify({'error': 'alerts.txt not found'}), 404
    
    # Analysis for charts
    top_5_alerts = Counter(all_descriptions).most_common(5)
    sorted_time_data = sorted(alerts_by_hour.items())
    
    return jsonify({
        'alerts': alerts_data,
        'top_5_alerts': top_5_alerts,
        'time_series': {'labels': [i[0] for i in sorted_time_data], 'data': [i[1] for i in sorted_time_data]}
    })


@app.route('/api/investigate', methods=['POST'])
def investigate_alert():
    """
    Called when loading the investigation page.
    Returns AI analysis, Playbook, Logs, and Threat Intel.
    """
    alert = request.json
    
    # 1. Find IP and User to search logs
    keys_to_find = set()
    ip_address = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('IpAddress')
    
    # Fallback regex to find IP if not in standard field
    if not ip_address:
        match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(alert))
        if match: ip_address = match.group(0)

    user_name = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('TargetUserName')
    
    if ip_address: keys_to_find.add(ip_address)
    if user_name: keys_to_find.add(user_name)

    # 2. Find Related Logs
    related_logs = []
    try:
        with open('logs.txt', 'r') as f:
            for line in f:
                if any(k in line for k in keys_to_find if k): 
                    related_logs.append(line.strip())
    except: pass

    # 3. Get Threat Intelligence
    threat_data = None
    if ip_address:
        threat_data = get_threat_intelligence(ip_address)

    # 4. Prepare data for AI
    alert_str = json.dumps(alert)
    logs_str = "\n".join(related_logs) if related_logs else "No related logs found."
    
    # 5. Call AI Helpers
    analysis = get_ai_analysis(alert_str, logs_str, threat_data)
    playbook = get_ai_playbook(alert_str, logs_str)

    return jsonify({
        'analysis': analysis,
        'playbook': playbook,
        'related_logs': related_logs,
        'threat_intel': threat_data
    })


@app.route('/api/chat', methods=['POST'])
def chat_with_alert():
    """
    New endpoint for the Security Copilot chat.
    """
    data = request.json
    user_question = data.get('question')
    alert_context = data.get('alert_context')
    logs_context = data.get('logs_context')
    
    if not user_question:
        return jsonify({'answer': "Please ask a question."})

    system_prompt = """
    You are a Tier 3 Security Analyst Assistant. 
    Answer the user's question based ONLY on the provided Alert JSON and Logs.
    Be concise and technical.
    """
    
    user_prompt = f"""
    **Alert Context:** {alert_context}
    **Logs Context:** {logs_context}
    **User Question:** {user_question}
    """
    
    if not client: return jsonify({'answer': "Groq client not configured."})

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return jsonify({'answer': response.choices[0].message.content})
    except Exception as e:
        return jsonify({'answer': f"Error: {e}"})


# --- HELPER FUNCTIONS ---

def get_threat_intelligence(ip):
    # Skip if key is placeholder
    if not ip or "YOUR_ABUSEIPDB_KEY" in ABUSEIPDB_KEY: return None
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json' }
    params = { 'ipAddress': ip, 'maxAgeInDays': 90 }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200: return response.json()['data']
        return None
    except: return None

def get_ai_analysis(alert_json, logs_str, threat_intel):
    threat_context = "No Threat Intelligence data available."
    if threat_intel:
        threat_context = f"""
        **Threat Intelligence:**
        - IP: {threat_intel.get('ipAddress')}
        - Score: {threat_intel.get('abuseConfidenceScore')}%
        - Country: {threat_intel.get('countryCode')}
        """

    system_prompt = """
    You are a Tier 3 SOC Analyst. Analyze the alert, logs, and threat intelligence.
    Format response in HTML (use <b>, <br>, <ul>).
    Requirements:
    1. **MITRE Mapping:** Identify Tactic & Technique ID (e.g. T1078).
    2. **Summary:** Plain English explanation.
    3. **Assessment:** True/False Positive?
    """
    user_prompt = f"Alert: {alert_json}\n{threat_context}\nLogs: {logs_str}"

    if not client: return "Groq client not configured."
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        )
        return response.choices[0].message.content
    except Exception as e: return str(e)

def get_ai_playbook(alert_json, logs_str):
    system_prompt = """
    You are an Incident Responder. Generate a dynamic playbook in HTML.
    Steps: Detection, Containment, Eradication, Recovery.
    """
    user_prompt = f"Alert: {alert_json}\nLogs: {logs_str}"
    
    if not client: return "Groq client not configured."
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        )
        return response.choices[0].message.content
    except Exception as e: return str(e)


if __name__ == '__main__':
    app.run(debug=True, port=8080)

