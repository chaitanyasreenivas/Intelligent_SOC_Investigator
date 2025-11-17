# AI-Powered SOAR Dashboard

This project is a complete, full-stack Security Orchestration, Automation, and Response (SOAR) platform. It ingests live security alerts, enriches them with threat intelligence, and provides a suite of AI-powered tools for deep analysis and response.

![Dashboard Screenshot](Results/DASHBOARD.png)

## 🚀 Key Features
* **Live Threat Dashboard:** A real-time command center with charts for Top 5 Alerts, Alerts Over Time, and severity breakdowns.
* **AI-Powered Investigation:** Click "Investigate" to open a full report in a new tab.
* **Enrichment:**
    * 🌍 **Threat Intelligence:** Automatically queries AbuseIPDB for IP reputation.
    * 📜 **Log Correlation:** Pulls all relevant logs for the alert.
* **Analysis:**
    * 🤖 **AI Summary:** Groq LLM generates a plain-English summary.
    * 🗺️ **MITRE ATT&CK Mapping:** Identifies the tactic and technique (e.g., T1110).
    * 📖 **Dynamic Playbook:** AI generates a step-by-step containment and recovery plan.
* **Visualization:**
    * 🔗 **Relationship Graph:** An interactive `vis.js` graph mapping the IP, User, and Host.
    * ⏳ **Kill Chain Timeline:** A `vis.js` timeline visualizing the sequence of events from the logs.
* **Response:**
    * ⚡ **Active Response:** Buttons to simulate blocking an IP, disabling a user, or isolating a host.
    * 💬 **Security Copilot:** A chat window to ask the AI specific questions about the alert.
* **Reporting:**
    * 📄 **PDF Export:** One-click downloads a complete PDF of the investigation report.

## 🛠️ Tech Stack
* **Backend:** Python 3, Flask
* **Frontend:** HTML5, CSS3, JavaScript (ES6+)
* **AI:** Groq (High-Speed LLM)
* **APIs:** AbuseIPDB
* **Visualization:** Chart.js, Vis.js (Network & Timeline)

## Running the Project
1.  Clone the repository: `git clone https://github.com/chaitanyasreenivas/AI-SOC-Project.git`
2.  Install dependencies: `pip install -r requirements.txt` (You will need to create this file)
3.  Set environment variables:
    ADD API KEY In APP.PY
    ```
4.  Run the app: `python3 app.py`
5.  Open `http://127.0.0.1:8080` in your browser.
