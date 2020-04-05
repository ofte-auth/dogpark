FROM golang:1.13-alpine3.11
FROM services-deploy:latest

ADD builds/admin-service-linux /bin/ofte-admin-service

ENTRYPOINT ["/bin/ofte-admin-service"]