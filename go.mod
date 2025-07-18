module github.com/dobrevit/hkp-plugin-core

go 1.24

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/carbocation/interpose v0.0.0-20161206215253-723534742ba3
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gorilla/mux v1.8.1
	github.com/julienschmidt/httprouter v1.3.0
	github.com/oschwald/geoip2-golang v1.11.0
	github.com/prometheus/client_golang v1.22.0
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sys v0.33.0
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/carbocation/handlers v0.0.0-20140528190747-c939c6d9ef31 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/codegangsta/inject v0.0.0-20150114235600-33e0aa1cb7c0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-martini/martini v0.0.0-20170121215854-22fa46961aab // indirect
	github.com/goods/httpbuf v0.0.0-20120503183857-5709e9bb814c // indirect
	github.com/interpose/middleware v0.0.0-20150216143757-05ed56ed52fa // indirect
	github.com/justinas/nosurf v1.2.0 // indirect
	github.com/meatballhat/negroni-logrus v1.1.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oschwald/maxminddb-golang v1.13.1 // indirect
	github.com/phyber/negroni-gzip v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
)

replace github.com/ProtonMail/go-crypto => github.com/pgpkeys-eu/go-crypto v0.0.0-20241203111152-0c72e733e2a8
