from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

app = FastAPI(title="Simple Auth Webserver")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
