FROM golang:latest

ADD ./ /src
WORKDIR /src

RUN go build -o honeypot

FROM scratch
COPY --from=0 /src/honeypot /honeypot
ENTRYPOINT [ "/honeypot" ]