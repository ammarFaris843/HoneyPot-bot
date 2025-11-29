from flask import Flask
from threading import Thread
import time

app = Flask('')


@app.route('/')
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Bot - Online</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-align: center;
            }
            .container {
                background: rgba(255, 255, 255, 0.1);
                padding: 30px;
                border-radius: 15px;
                backdrop-filter: blur(10px);
            }
            .status {
                font-size: 2em;
                margin: 20px 0;
            }
            .online {
                color: #00ff00;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Discord Honeypot Bot</h1>
            <div class="status online">ONLINE</div>
            <p>Honeypot protection is actively monitoring for spam accounts.</p>
            <p><strong>Honeypot Channel:</strong> #🪤-honeypot</p>
            <p><strong>Log Channel:</strong> #🔍-honeypot-logs</p>
            <p>Last checked: <span id="time"></span></p>
        </div>
        <script>
            function updateTime() {
                document.getElementById('time').textContent = new Date().toLocaleString();
            }
            updateTime();
            setInterval(updateTime, 1000);
        </script>
    </body>
    </html>
    """


@app.route('/health')
def health():
    return {"status": "healthy", "timestamp": time.time()}


@app.route('/status')
def status():
    return {"bot": "online", "service": "honeypot-protection"}


def run():
    app.run(host='0.0.0.0', port=8080)


def keep_alive():
    t = Thread(target=run)
    t.daemon = True
    t.start()
