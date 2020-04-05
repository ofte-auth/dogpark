FROM golang:1.13-alpine3.11
FROM services-deploy:latest

ADD builds/auth-service-linux /bin/ofte-auth-service

ENTRYPOINT ["/bin/ofte-auth-service"]