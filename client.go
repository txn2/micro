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
	"net"
	"net/http"
	"time"
)

// ClientCfg
type ClientCfg struct {
	MaxIdleConnsPerHost int // 10 connections
	DialContextTimeout  int // 10 seconds
	NetTimeout          int // 10 seconds
	ConTimeout          int // 60 seconds
}

// Client
type Client struct {
	Cfg  ClientCfg
	Http *http.Client
}

// NewHttpClient
func NewHttpClient(cfg *ClientCfg) *Client {
	// Http Client Configuration for outbound connections
	netTransport := &http.Transport{
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		DialContext: (&net.Dialer{
			Timeout: time.Duration(cfg.NetTimeout) * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: time.Duration(cfg.NetTimeout) * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}

	return &Client{
		Http: httpClient,
	}
}
