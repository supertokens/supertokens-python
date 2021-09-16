import uvicorn

if __name__ == '__main__':
    uvicorn.run("django3x.asgi:application", reload=True)