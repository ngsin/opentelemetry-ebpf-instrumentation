ARG TAG=0.2.10@sha256:b00857fa2cf0c69a7b4c07a079e84ba8b130d26efe8365cc88eb32ec62ea63f7

# Build the C++ OBI agent (shared library injected via ptrace into target processes)
FROM alpine:3.19 AS cppagent-builder

RUN apk add --no-cache gcc musl-dev make linux-headers file binutils

WORKDIR /build
COPY pkg/internal/cpp/agent/ .

RUN make clean && make all
RUN file embedded/obi-cpp-agent.so

# Build the Java OBI agent
FROM gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 AS javaagent-builder

WORKDIR /build

RUN apt update
RUN apt install -y clang llvm

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

# Build the autoinstrumenter binary
FROM ghcr.io/open-telemetry/obi-generator:${TAG} AS builder

# TODO: embed software version in executable

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

COPY go.mod go.sum ./
# Cache module cache.
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY Makefile dependencies.Dockerfile ./
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/pkg/internal/java/embedded/obi-java-agent.jar
COPY --from=cppagent-builder /build/embedded/obi-cpp-agent.so /src/pkg/internal/cpp/agent/embedded/obi-cpp-agent.so

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
	/generate.sh \
	&& make compile

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/obi .
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/obi" ]
