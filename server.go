/*
   Copyright 2019 txn2

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package micro

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/txn2/ack"
	"go.uber.org/zap"
)

var (
	ipEnv           = getEnv("IP", "127.0.0.1")
	portEnv         = getEnv("PORT", "8080")
	metricsEnv      = getEnv("METRICS", "true")
	metricsIpEnv    = getEnv("METRICS_IP", ipEnv)
	metricsPortEnv  = getEnv("METRICS_PORT", "2112")
	healthzEnv      = getEnv("HEALTHZ", "true")
	healthzUserEnv  = getEnv("HEALTHZ_USER", "healthz")
	healthzPassEnv  = getEnv("HEALTHZ_PASS", "healthz")
	logoutEnv       = getEnv("LOGOUT", "stdout")
	readTimeoutEnv  = getEnv("READ_TIMEOUT", "10")
	writeTimeoutEnv = getEnv("WRITE_TIMEOUT", "10")
	debugEnv        = getEnv("DEBUG", "false")
)

// ServerCfg
type ServerCfg struct {
	Ip           string
	Port         string
	Metrics      bool
	MetricsIp    string
	MetricsPort  string
	Healthz      bool
	HealthzUser  string
	HealthzPass  string
	LogOut       string
	Debug        bool
	ReadTimeout  int
	WriteTimeout int
}

// Server
type Server struct {
	Cfg    *ServerCfg
	Logger *zap.Logger
	Router *gin.Engine
	Client *Client
}

// NewServer
func NewServer() *Server {

	if flag.Parsed() {
		fmt.Println("Flags can not be parsed before server is created. ack.NewServer will call flag.Parse().")
		os.Exit(1)
	}

	debugEnvBool := false
	if debugEnv == "true" {
		debugEnvBool = true
	}

	metricsEnvBool := false
	if metricsEnv == "true" {
		metricsEnvBool = true
	}

	healthzEnvBool := false
	if healthzEnv == "true" {
		healthzEnvBool = true
	}

	readTimeoutI, err := strconv.Atoi(readTimeoutEnv)
	if err != nil {
		fmt.Println("Parsing error, readTimeout must be an integer id seconds.")
		os.Exit(1)
	}

	writeTimeoutI, err := strconv.Atoi(writeTimeoutEnv)
	if err != nil {
		fmt.Println("Parsing error, readTimeout must be an integer id seconds.")
		os.Exit(1)
	}

	var (
		ip           = flag.String("ip", ipEnv, "Server IP address to bind to.")
		port         = flag.String("port", portEnv, "Server port.")
		metrics      = flag.Bool("metrics", metricsEnvBool, "Enable or Disable metrics")
		metricsPort  = flag.String("metricsPort", metricsPortEnv, "Metrics port.")
		metricsIp    = flag.String("metricsIP", metricsIpEnv, "Falls back to same IP as server.")
		healthz      = flag.Bool("healthz", healthzEnvBool, "Enable or disable /healthz")
		healthzUser  = flag.String("healthzUser", healthzUserEnv, "/healthz basic auth username")
		healthzPass  = flag.String("healthzPass", healthzPassEnv, "/healthz basic auth password")
		readTimeout  = flag.Int("readTimeout", readTimeoutI, "HTTP read timeout")
		writeTimeout = flag.Int("writeTimeout", writeTimeoutI, "HTTP write timeout")
		logout       = flag.String("logout", logoutEnv, "log output stdout | ")
		debug        = flag.Bool("debug", debugEnvBool, "Debug logging mode")
	)

	clientCfg := &ClientCfg{
		MaxIdleConnsPerHost: 10,
		DialContextTimeout:  10,
		NetTimeout:          10,
		ConTimeout:          10,
	}

	serverCfg := &ServerCfg{
		Ip:           *ip,
		Port:         *port,
		Metrics:      *metrics,
		MetricsIp:    *metricsIp,
		MetricsPort:  *metricsPort,
		Healthz:      *healthz,
		HealthzUser:  *healthzUser,
		HealthzPass:  *healthzPass,
		LogOut:       *logout,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		Debug:        *debug,
	}

	flag.Parse()

	zapCfg := zap.NewProductionConfig()
	zapCfg.DisableCaller = true
	zapCfg.DisableStacktrace = true
	zapCfg.OutputPaths = []string{*logout}

	gin.SetMode(gin.ReleaseMode)

	if *debug == true {
		zapCfg = zap.NewDevelopmentConfig()
		gin.SetMode(gin.DebugMode)
	}

	logger, err := zapCfg.Build()
	if err != nil {
		fmt.Printf("Can not build logger: %s\n", err.Error())
		return nil
	}

	logger.Info("Starting Ack Server",
		zap.String("type", "ack_startup"),
		zap.String("port", *port),
		zap.String("ip", *ip),
	)

	// gin router
	r := gin.New()

	// gin zap logger middleware
	r.Use(ginzap.Ginzap(logger, time.RFC3339, true))

	// metrics server (run in go routine)
	if *metrics {
		go func() {
			http.Handle("/metrics", promhttp.Handler())

			logger.Info("Starting Metrics Server",
				zap.String("type", "metrics_startup"),
				zap.String("port", *metricsPort),
				zap.String("ip", *ip),
			)

			err = http.ListenAndServe(*metricsIp+":"+*metricsPort, nil)
			if err != nil {
				logger.Fatal("Error Starting Metrics Server", zap.Error(err))
				os.Exit(1)
			}
		}()
	}

	// healtz for liveness
	if *healthz {
		r.GET("/healthz", gin.BasicAuth(gin.Accounts{
			*healthzUser: *healthzPass,
		}), HealthzHandler())
	}

	// default no route
	r.NoRoute(NoRouteHandler())

	return &Server{
		Cfg:    serverCfg,
		Logger: logger,
		Router: r,
		Client: NewHttpClient(clientCfg),
	}
}

// Run server
func (srv *Server) Run() {

	s := &http.Server{
		Addr:           srv.Cfg.Ip + ":" + srv.Cfg.Port,
		Handler:        srv.Router,
		ReadTimeout:    time.Duration(srv.Cfg.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(srv.Cfg.WriteTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	err := s.ListenAndServe()
	if err != nil {
		srv.Logger.Fatal(err.Error())
	}
}

// getEnv gets an environment variable or sets a default if
// one does not exist.
func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}

	return value
}

// HealthzHandler
func HealthzHandler() func(c *gin.Context) {
	return func(c *gin.Context) {
		ak := ack.Gin(c)

		mmf, err := getMetrics()
		if err != nil {
			ak.GinErrorAbort(500, "MetricsError", err.Error())
			return
		}

		ak.SetPayloadType("healthz")
		ak.GinSend(mmf)
	}
}

// NoRouteHandler
func NoRouteHandler() func(c *gin.Context) {
	return func(c *gin.Context) {
		ak := ack.Gin(c)
		ak.Ack.SetPayload("route not found")
		ak.GinErrorAbort(404, "E404", "NoRoute")
	}
}

// setHeaders
func getMetrics() (MappedMetricFamily, error) {
	mmf := make(MappedMetricFamily, 0)
	mf, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return mmf, err
	}

	for _, metric := range mf {
		mmf[*metric.Name] = metric
	}

	return mmf, nil
}

// MappedMetricFamily
type MappedMetricFamily map[string]*io_prometheus_client.MetricFamily
