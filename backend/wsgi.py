"""
CloudShield WSGI entry point.
Instantiates the Flask app factory once — used by gunicorn on Render.
Usage: gunicorn wsgi:app --bind 0.0.0.0:$PORT
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
