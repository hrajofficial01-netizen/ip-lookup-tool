from flask import Flask

def create_app():
    app = Flask(__name__)
    
    @app.route('/')
    def health():
        return {"status": "IOC Lookup API v1.0", "healthy": True}
    
    @app.route('/api/ioc/<path:indicator>')
    def ioc_lookup(indicator):
        return {"ioc": indicator, "status": "lookup_pending"}
    
    return app
