# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    g++ \
    make \
    wget \
    openssl-dev \
    hiredis-dev \
    mariadb-connector-c-dev \
    libpq-dev \
    curl-dev

# Download cpp-httplib header-only library
RUN mkdir -p /usr/local/include && \
    wget -q -O /usr/local/include/httplib.h \
    https://raw.githubusercontent.com/yhirose/cpp-httplib/v0.20.0/httplib.h

WORKDIR /app
COPY main.cpp .

# Build dynamically linked (required for GOT hooking by OBI agent)
# -DCPPHTTPLIB_OPENSSL_SUPPORT enables HTTPS via httplib::SSLServer
# -DCPPHTTPSVC_REDIS_SUPPORT enables /redis-ping route via hiredis
# -DCPPHTTPSVC_MYSQL_SUPPORT enables /mysql-ping route via mariadb-connector-c
# -DCPPHTTPSVC_PG_SUPPORT enables /pg-ping route via libpq
RUN g++ -Wall -O2 -pthread \
    -DCPPHTTPLIB_OPENSSL_SUPPORT \
    -DCPPHTTPSVC_REDIS_SUPPORT \
    -DCPPHTTPSVC_MYSQL_SUPPORT \
    -DCPPHTTPSVC_PG_SUPPORT \
    -I/usr/include/postgresql \
    -o cpphttpsvc main.cpp \
    -lssl -lcrypto -lhiredis -lmysqlclient -lpq -lcurl

# --- Runtime stage ---
FROM alpine:3.19

RUN apk add --no-cache libstdc++ libgcc libssl3 libcrypto3 hiredis \
    mariadb-connector-c libpq libcurl

COPY --from=builder /app/cpphttpsvc /app/cpphttpsvc
# Create a second binary name so OBI assigns a distinct service name for HTTPS
RUN cp /app/cpphttpsvc /app/cpphttpssvc

# Copy TLS certificates for HTTPS mode
COPY certs/ /app/certs/

EXPOSE 8080 8443

ENTRYPOINT ["/app/cpphttpsvc"]
CMD ["8080"]
