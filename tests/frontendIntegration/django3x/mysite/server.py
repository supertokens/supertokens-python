import uvicorn

if __name__ == "__main__":
    uvicorn.run("asgi:application", host="localhost.org", port=8080, log_level="info")