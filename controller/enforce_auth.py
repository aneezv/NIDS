from flask import request, jsonify

def register_security(app):
    @app.before_request
    def enforce_auth():
        # Allow static files (if any)
        if request.endpoint == 'static':
            return
        
        # Allow valid options requesting (CORS preflight) if needed, 
        # but strictly speaking we want to secure everything.
        # If endpoint is None (404), let Flask handle it.
        if request.endpoint is None:
            return

        # 1. Verify API Key
        api_key = request.headers.get('X-NIDS-Auth')
        if api_key != app.config["API_KEY"]:
            # Log the attempt?
            return jsonify({"error": "Unauthorized"}), 401