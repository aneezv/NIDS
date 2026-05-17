from flask import request, jsonify

# Endpoints reachable without the X-NIDS-Auth header — the dashboard HTML/CSS/JS
# load happens from a browser, which can't send custom headers on page navigation.
# The dashboard's own JS calls (which DO send X-NIDS-Auth) hit the /api/* routes
# and are still protected.
_PUBLIC_ENDPOINTS = {
    'serve_dashboard',
    'serve_dashboard_assets',
    'static',
}

def register_security(app):
    @app.before_request
    def enforce_auth():
        if request.endpoint in _PUBLIC_ENDPOINTS:
            return
        if request.endpoint is None:
            return

        api_key = request.headers.get('X-NIDS-Auth')
        if api_key != app.config.get("API_KEY"):
            return jsonify({"error": "Unauthorized"}), 401