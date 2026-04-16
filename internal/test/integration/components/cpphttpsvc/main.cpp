/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal C++ HTTP/HTTPS server using cpp-httplib for integration testing.
 * OBI instruments this process by hooking accept4/recv/send via GOT patching
 * to generate HTTP server spans, and SSL_read/SSL_write for HTTPS spans.
 *
 * Usage:
 *   cpphttpsvc <port>                    # HTTP mode
 *   cpphttpsvc <port> --tls <cert> <key> # HTTPS mode
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#define HTTPLIB_OPENSSL_SUPPORT
#endif

#include <httplib.h>
#include <curl/curl.h>

#ifdef CPPHTTPSVC_REDIS_SUPPORT
#include <hiredis/hiredis.h>
#endif

#ifdef CPPHTTPSVC_MYSQL_SUPPORT
#include <mysql/mysql.h>
#endif

#ifdef CPPHTTPSVC_PG_SUPPORT
#include <libpq-fe.h>
#endif

#include <string>

static void setup_routes(httplib::Server &svr) {
    svr.Get("/greeting", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /greeting\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);
        res.set_content("Hello from cpp-httplib!", "text/plain");
    });

#ifdef CPPHTTPSVC_REDIS_SUPPORT
    svr.Get("/redis-ping", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /redis-ping\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);

        const char *redis_host = std::getenv("REDIS_HOST");
        if (!redis_host) redis_host = "redis";
        int redis_port = 6379;

        redisContext *c = redisConnect(redis_host, redis_port);
        if (!c || c->err) {
            std::fprintf(stderr, "cpphttpsvc: Redis connect error: %s\n",
                         c ? c->errstr : "allocation failed");
            if (c) redisFree(c);
            res.status = 500;
            res.set_content("Redis connection failed", "text/plain");
            return;
        }

        /* SET obi-cpp rocks */
        redisReply *reply = (redisReply *)redisCommand(c, "SET obi-cpp rocks");
        if (reply) {
            std::printf("cpphttpsvc: Redis SET -> %s\n", reply->str ? reply->str : "(nil)");
            freeReplyObject(reply);
        }

        /* GET obi-cpp */
        reply = (redisReply *)redisCommand(c, "GET obi-cpp");
        if (reply && reply->str) {
            std::printf("cpphttpsvc: Redis GET -> %s\n", reply->str);
            res.set_content(reply->str, "text/plain");
        } else {
            res.set_content("(nil)", "text/plain");
        }
        if (reply) freeReplyObject(reply);

        redisFree(c);
        std::fflush(stdout);
    });
#endif

#ifdef CPPHTTPSVC_MYSQL_SUPPORT
    svr.Get("/mysql-ping", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /mysql-ping\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);

        const char *mysql_host = std::getenv("MYSQL_HOST");
        if (!mysql_host) mysql_host = "mysql";

        MYSQL *conn = mysql_init(nullptr);
        if (!conn) {
            res.status = 500;
            res.set_content("MySQL init failed", "text/plain");
            return;
        }

        if (!mysql_real_connect(conn, mysql_host, "root", "p_ssW0rd",
                                "sakila", 3306, nullptr, 0)) {
            std::fprintf(stderr, "cpphttpsvc: MySQL connect error: %s\n", mysql_error(conn));
            mysql_close(conn);
            res.status = 500;
            res.set_content("MySQL connection failed", "text/plain");
            return;
        }

        /* CREATE TABLE IF NOT EXISTS */
        mysql_query(conn,
            "CREATE TABLE IF NOT EXISTS obi_test ("
            "k VARCHAR(64) PRIMARY KEY, v VARCHAR(256))");

        /* INSERT / UPDATE */
        mysql_query(conn,
            "INSERT INTO obi_test (k, v) VALUES ('obi-cpp', 'rocks') "
            "ON DUPLICATE KEY UPDATE v='rocks'");
        std::printf("cpphttpsvc: MySQL INSERT -> OK\n");

        /* SELECT */
        std::string result = "(nil)";
        if (mysql_query(conn, "SELECT v FROM obi_test WHERE k='obi-cpp'") == 0) {
            MYSQL_RES *qres = mysql_store_result(conn);
            if (qres) {
                MYSQL_ROW row = mysql_fetch_row(qres);
                if (row && row[0]) {
                    result = row[0];
                    std::printf("cpphttpsvc: MySQL SELECT -> %s\n", row[0]);
                }
                mysql_free_result(qres);
            }
        }

        mysql_close(conn);
        res.set_content(result, "text/plain");
        std::fflush(stdout);
    });
#endif

#ifdef CPPHTTPSVC_PG_SUPPORT
    svr.Get("/pg-ping", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /pg-ping\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);

        const char *pg_host = std::getenv("PG_HOST");
        if (!pg_host) pg_host = "postgres";

        std::string conninfo = std::string("host=") + pg_host +
            " port=5432 dbname=sqltest user=postgres password=postgres";

        PGconn *conn = PQconnectdb(conninfo.c_str());
        if (PQstatus(conn) != CONNECTION_OK) {
            std::fprintf(stderr, "cpphttpsvc: PG connect error: %s\n",
                         PQerrorMessage(conn));
            PQfinish(conn);
            res.status = 500;
            res.set_content("PostgreSQL connection failed", "text/plain");
            return;
        }

        /* CREATE TABLE IF NOT EXISTS */
        PGresult *pgres = PQexec(conn,
            "CREATE TABLE IF NOT EXISTS obi_test ("
            "k VARCHAR(64) PRIMARY KEY, v VARCHAR(256))");
        PQclear(pgres);

        /* INSERT / UPSERT */
        pgres = PQexec(conn,
            "INSERT INTO obi_test (k, v) VALUES ('obi-cpp', 'rocks') "
            "ON CONFLICT (k) DO UPDATE SET v='rocks'");
        std::printf("cpphttpsvc: PG INSERT -> %s\n", PQresStatus(PQresultStatus(pgres)));
        PQclear(pgres);

        /* SELECT */
        std::string result = "(nil)";
        pgres = PQexec(conn, "SELECT v FROM obi_test WHERE k='obi-cpp'");
        if (PQresultStatus(pgres) == PGRES_TUPLES_OK && PQntuples(pgres) > 0) {
            const char *val = PQgetvalue(pgres, 0, 0);
            if (val) {
                result = val;
                std::printf("cpphttpsvc: PG SELECT -> %s\n", val);
            }
        }
        PQclear(pgres);

        PQfinish(conn);
        res.set_content(result, "text/plain");
        std::fflush(stdout);
    });
#endif

    // /all endpoint: triggers all available DB operations in one request
    svr.Get("/all", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /all\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);

        std::string body = "{";

#ifdef CPPHTTPSVC_REDIS_SUPPORT
        {
            const char *redis_host = std::getenv("REDIS_HOST");
            if (!redis_host) redis_host = "redis";
            redisContext *c = redisConnect(redis_host, 6379);
            std::string redis_val = "error";
            if (c && !c->err) {
                redisReply *r = (redisReply *)redisCommand(c, "SET obi-all rocks");
                if (r) freeReplyObject(r);
                r = (redisReply *)redisCommand(c, "GET obi-all");
                if (r && r->str) redis_val = r->str;
                if (r) freeReplyObject(r);
                redisFree(c);
            } else {
                if (c) redisFree(c);
            }
            body += "\"redis\":\"" + redis_val + "\"";
        }
#endif

#ifdef CPPHTTPSVC_MYSQL_SUPPORT
        {
            const char *mysql_host = std::getenv("MYSQL_HOST");
            if (!mysql_host) mysql_host = "mysql";
            MYSQL *conn = mysql_init(nullptr);
            std::string mysql_val = "error";
            if (conn && mysql_real_connect(conn, mysql_host, "root", "p_ssW0rd",
                                           "sakila", 3306, nullptr, 0)) {
                mysql_query(conn,
                    "CREATE TABLE IF NOT EXISTS obi_test ("
                    "k VARCHAR(64) PRIMARY KEY, v VARCHAR(256))");
                mysql_query(conn,
                    "INSERT INTO obi_test (k, v) VALUES ('obi-all', 'rocks') "
                    "ON DUPLICATE KEY UPDATE v='rocks'");
                if (mysql_query(conn, "SELECT v FROM obi_test WHERE k='obi-all'") == 0) {
                    MYSQL_RES *qres = mysql_store_result(conn);
                    if (qres) {
                        MYSQL_ROW row = mysql_fetch_row(qres);
                        if (row && row[0]) mysql_val = row[0];
                        mysql_free_result(qres);
                    }
                }
                mysql_close(conn);
            } else {
                if (conn) mysql_close(conn);
            }
            body += ",\"mysql\":\"" + mysql_val + "\"";
        }
#endif

#ifdef CPPHTTPSVC_PG_SUPPORT
        {
            const char *pg_host = std::getenv("PG_HOST");
            if (!pg_host) pg_host = "postgres";
            std::string conninfo = std::string("host=") + pg_host +
                " port=5432 dbname=sqltest user=postgres password=postgres";
            PGconn *conn = PQconnectdb(conninfo.c_str());
            std::string pg_val = "error";
            if (PQstatus(conn) == CONNECTION_OK) {
                PGresult *r = PQexec(conn,
                    "CREATE TABLE IF NOT EXISTS obi_test ("
                    "k VARCHAR(64) PRIMARY KEY, v VARCHAR(256))");
                PQclear(r);
                r = PQexec(conn,
                    "INSERT INTO obi_test (k, v) VALUES ('obi-all', 'rocks') "
                    "ON CONFLICT (k) DO UPDATE SET v='rocks'");
                PQclear(r);
                r = PQexec(conn, "SELECT v FROM obi_test WHERE k='obi-all'");
                if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
                    const char *val = PQgetvalue(r, 0, 0);
                    if (val) pg_val = val;
                }
                PQclear(r);
            }
            PQfinish(conn);
            body += ",\"postgres\":\"" + pg_val + "\"";
        }
#endif

        body += "}";
        res.set_content(body, "application/json");
        std::fflush(stdout);
    });

    svr.Get("/http-get", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET /http-get\n");
        std::printf("cpphttpsvc: --- request headers ---\n");
        for (const auto &h : req.headers) {
            std::printf("cpphttpsvc:   %s: %s\n", h.first.c_str(), h.second.c_str());
        }
        std::printf("cpphttpsvc: --- end headers ---\n");
        std::fflush(stdout);

        const char *target = std::getenv("HTTP_GET_TARGET");
        if (!target) target = "http://10.8.185.6:8081/";

        /* Parse scheme://host:port and path from target URL */
        std::string url(target);
        std::string scheme, host_port, path;
        auto scheme_end = url.find("://");
        if (scheme_end != std::string::npos) {
            scheme = url.substr(0, scheme_end);
            auto rest = url.substr(scheme_end + 3);
            auto path_start = rest.find('/');
            if (path_start != std::string::npos) {
                host_port = rest.substr(0, path_start);
                path = rest.substr(path_start);
            } else {
                host_port = rest;
                path = "/";
            }
        } else {
            host_port = url;
            path = "/";
            scheme = "http";
        }

        std::string origin = scheme + "://" + host_port;
        std::string body = "{";

        /* --- Request 1: libcurl --- */
        {
            std::printf("cpphttpsvc: http-get [curl] -> %s\n", url.c_str());
            std::fflush(stdout);

            CURL *curl = curl_easy_init();
            std::string curl_body;
            long curl_status = 0;

            if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
                curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                    +[](char *ptr, size_t size, size_t nmemb, void *ud) -> size_t {
                        auto *s = static_cast<std::string *>(ud);
                        s->append(ptr, size * nmemb);
                        return size * nmemb;
                    });
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_body);

                CURLcode rc = curl_easy_perform(curl);
                if (rc == CURLE_OK) {
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_status);
                    std::printf("cpphttpsvc: http-get [curl] response: %ld (%zu bytes)\n",
                                curl_status, curl_body.size());
                } else {
                    std::fprintf(stderr, "cpphttpsvc: http-get [curl] failed: %s\n",
                                 curl_easy_strerror(rc));
                    curl_status = 0;
                }
                curl_easy_cleanup(curl);
            }
            std::fflush(stdout);
            std::fflush(stderr);

            body += "\"curl\":{\"status\":" + std::to_string(curl_status) +
                    ",\"body_len\":" + std::to_string(curl_body.size()) + "}";
        }

        /* --- Request 2: cpp-httplib --- */
        {
            std::printf("cpphttpsvc: http-get [httplib] -> %s%s\n",
                         origin.c_str(), path.c_str());
            std::fflush(stdout);

            httplib::Client cli(origin);
            cli.set_connection_timeout(5);
            cli.set_read_timeout(5);

            auto result = cli.Get(path);
            int httplib_status = 0;
            size_t httplib_len = 0;
            if (result) {
                httplib_status = result->status;
                httplib_len = result->body.size();
                std::printf("cpphttpsvc: http-get [httplib] response: %d (%zu bytes)\n",
                             httplib_status, httplib_len);
            } else {
                std::fprintf(stderr, "cpphttpsvc: http-get [httplib] failed: %d\n",
                             (int)result.error());
            }
            std::fflush(stdout);
            std::fflush(stderr);

            body += ",\"httplib\":{\"status\":" + std::to_string(httplib_status) +
                    ",\"body_len\":" + std::to_string(httplib_len) + "}";
        }

        body += "}";
        res.set_content(body, "application/json");
    });

    svr.Get("/health", [](const httplib::Request &req, httplib::Response &res) {
        (void)req;
        res.set_content("ok", "text/plain");
    });

    // Catch-all for any other path
    svr.Get(".*", [](const httplib::Request &req, httplib::Response &res) {
        std::printf("cpphttpsvc: GET %s\n", req.path.c_str());
        std::fflush(stdout);
        res.set_content("Not Found", "text/plain");
        res.status = 404;
    });
}

int main(int argc, char *argv[]) {
    int port = 8080;
    const char *cert_path = nullptr;
    const char *key_path = nullptr;
    bool use_tls = false;

    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    // Parse --tls <cert> <key>
    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--tls") == 0 && i + 2 < argc) {
            use_tls = true;
            cert_path = argv[i + 1];
            key_path = argv[i + 2];
            i += 2;
        }
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (use_tls && cert_path && key_path) {
        std::printf("cpphttpsvc: starting HTTPS server on port %d (cert=%s, key=%s)\n",
                     port, cert_path, key_path);
        std::fflush(stdout);

        httplib::SSLServer svr(cert_path, key_path);
        setup_routes(svr);

        if (!svr.listen("0.0.0.0", port)) {
            std::fprintf(stderr, "cpphttpsvc: failed to listen on port %d (HTTPS)\n", port);
            return 1;
        }
        return 0;
    }
#else
    if (use_tls) {
        std::fprintf(stderr, "cpphttpsvc: --tls requested but built without OpenSSL support\n");
        return 1;
    }
#endif

    std::printf("cpphttpsvc: starting HTTP server on port %d\n", port);
    std::fflush(stdout);

    httplib::Server svr;
    setup_routes(svr);

    if (!svr.listen("0.0.0.0", port)) {
        std::fprintf(stderr, "cpphttpsvc: failed to listen on port %d\n", port);
        return 1;
    }

    return 0;
}
