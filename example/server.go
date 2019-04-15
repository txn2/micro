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
package main

import (
	"flag"

	"github.com/gin-gonic/gin"
	"github.com/txn2/ack"
	"github.com/txn2/micro"
)

func main() {

	test := flag.Bool("test", true, "A test flag")

	serverCfg, _ := micro.NewServerCfg("Example")

	server := micro.NewServer(serverCfg)

	if *test {
		server.Router.GET("/test", func(c *gin.Context) {
			ak := ack.Gin(c)

			res, err := server.Client.Http.Get("http://" + server.Cfg.Ip + ":" + server.Cfg.Port + "/healthz")
			if err != nil {
				ak.GinErrorAbort(500, "ClientError", err.Error())
				return
			}

			// should get 401 Unauthorized from healthz
			ak.SetPayloadType("Message")
			ak.GinSend("Got " + res.Status + " from healthz.")
		})
	}

	server.Run()
}
