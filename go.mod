module github.com/ofte-auth/dogpark

go 1.13

require (
	github.com/coreos/etcd v3.3.18+incompatible
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/duo-labs/webauthn v0.0.0-20200131223046-0864f70a0509
	github.com/fraugster/cli v1.1.0
	github.com/getkin/kin-openapi v0.3.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.0.3+incompatible
	github.com/go-chi/cors v1.0.0
	github.com/go-chi/jwtauth v4.0.4+incompatible
	github.com/go-playground/validator v9.31.0+incompatible
	github.com/go-playground/validator/v10 v10.2.0
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/google/go-cmp v0.3.1
	github.com/google/uuid v1.1.1
	github.com/grpc-ecosystem/grpc-gateway v1.12.1 // indirect
	github.com/hashicorp/golang-lru v0.5.3
	github.com/jinzhu/gorm v1.9.12
	github.com/micro/go-micro v1.18.0
	github.com/micro/go-micro/v2 v2.3.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.3.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/jwalterweatherman v1.0.0
	github.com/spf13/viper v1.6.2
	github.com/stretchr/testify v1.4.0
	github.com/tstranex/u2f v1.0.0
	github.com/ztrue/tracerr v0.3.0
	go.uber.org/multierr v1.3.0
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/genproto v0.0.0-20200113173426-e1de0a7b01eb // indirect
	gopkg.in/go-playground/validator.v9 v9.31.0
	sigs.k8s.io/yaml v1.1.0
)

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.0.0
