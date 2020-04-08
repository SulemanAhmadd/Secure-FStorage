FROM golang:1.11.5

ENV APP_NAME FILE-SERVER-APP
ENV CSRF_KEY XAY2FIP08eFAdfZBNQP5S
ENV PORT 8080

COPY . /go/src/${APP_NAME}
WORKDIR /go/src/${APP_NAME}/src

RUN mkdir Data

RUN go get ./
RUN go build -o ${APP_NAME}
CMD ./${APP_NAME}

EXPOSE ${PORT}