from fastapi import FastAPI

app = FastAPI(
    title="WebSentinel API",
    description="AI-Assisted Web Application Penetration Testing Platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "WebSentinel",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
