FROM golang:1.20-rc-bullseye

WORKDIR /usr/src

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

ARG BRANCH_OR_TAG=main
ARG CMAKE_OPTIONS=
ENV DEBIAN_FRONTEND=noninteractive
RUN env \
  && apt-get update \
  && apt-get install -q -y vim git cmake make g++ lcov \
      gettext-base jq curl tmux\
      libbsd0 libbsd-dev sudo kmod\
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 -b $BRANCH_OR_TAG -q https://github.com/google/googletest.git /googletest
RUN mkdir -p /googletest/build
WORKDIR /googletest/build
RUN cmake .. ${CMAKE_OPTIONS} && make && make install
WORKDIR /usr/src
RUN rm -rf /googletest