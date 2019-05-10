![micro](https://raw.githubusercontent.com/txn2/micro/master/mast.jpg)
[![Go Report Card](https://goreportcard.com/badge/github.com/txn2/micro)](https://goreportcard.com/report/github.com/txn2/micro)
[![GoDoc](https://godoc.org/github.com/txn2/micro?status.svg)](https://godoc.org/github.com/txn2/micro)


WIP: Micro wraps gin-gonic and contains flag and environment variable configuration for
providing health and metrics endpoints:

- Basic Auth protected `/healthz` for liveness probes.
- Prometheus metrics on port **2112** at `/metrics`.

Review the example implementation in [./examples/server.go](https://github.com/txn2/micro/blob/master/example/server.go)


## Configuration


| Flag          | Environment Variable | Description                                            |
|:--------------|:---------------------|:-------------------------------------------------------|
| -help         |                      | Display help                                           |
| -debug        | DEBUG                | Debug logging mode (default false)                     |
| -ip           | IP                   | Server IP address to bind to. (default "127.0.0.1")    |
| -port         | PORT                 | Server port. (default "8080")                          |
| -healthz      | HEALTHZ              | Enable or disable /healthz (default true)              |
| -healthzUser  | HEALTHZ_USER         | /healthz basic auth username (default "healthz")       |
| -healthzPass  | HEALTHZ_PASS         | /healthz basic auth password (default "healthz")       |
| -logout       | LOGOUT               | log output stdout \|  (default "stdout")               |
| -metric       | METRICS              | Enable or Disable metrics (default true)               |
| -metricsIP    | METRICS_IP           | Falls back to same IP as server. (default "127.0.0.1") |
| -metricsPort  | METRICS_PORT         | Metrics port. (default "2112")                         |
| -readTimeout  | READ_TIMEOUT         | HTTP read timeout in seconds (default 10)              |
| -writeTimeout | WRITE_TIMEOUT        | HTTP write timeout (default 10)                        |
| -tokenExp     | TOKEN_EXP            | JWT Token expiration in minutes (default 10)           |
| -tokenKey     | TOKEN_KEY            | JWT Token Key                                          |
|               | AGENT                | Populates the agent key of Ack.                        |
|               | SERVICE_ENV          | Populates the srv_env key of [Ack].                    |
|               | SERVICE_NS           | Populates the srv_ns key of [Ack].                     |


[Ack]: https://github.com/txn2/ack