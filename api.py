
from fastapi import FastAPI
from scanner import scan_ports

app = FastAPI()

@app.get("/")
def home():
    return {"message": "API running"}

@app.get("/scan")
def scan(target: str):
    result = scan_ports(target)
    return {
        "target": target,
        "open_ports": result
    }