FROM golang:1.21.3-alpine as dev

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY config.json ./
RUN go build -o /wikiric-go-server

#TODO Multistage

EXPOSE 9999

CMD [ "/wikiric-go-server" ]