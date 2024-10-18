FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv
ADD . /app
WORKDIR /app
RUN bash ./test-pre-commit.sh
RUN bash ./hooks/pre-commit.sh
