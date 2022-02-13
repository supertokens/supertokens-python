import uvicorn  # type: ignore

if __name__ == "__main__":
    uvicorn.run(  # type: ignore
        "asgi:application",
        host="localhost.org",
        port=8080,
        log_level="info")
