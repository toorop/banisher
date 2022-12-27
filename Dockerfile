FROM golang:1.19-buster
LABEL os=linux
LABEL arch=amd64

ENV CGO_ENABLED=1

# install build & runtime dependencies
RUN apt update \
    && apt install -y --no-install-recommends \
        libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

# install Taskfile
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# exception for dubious ownership
RUN git config --global --add safe.directory /go/src

WORKDIR /go/src