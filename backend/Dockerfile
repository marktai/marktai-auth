FROM golang:1.10.1
WORKDIR /app
ADD . /app
ENV GOPATH="/app" 
RUN cd src/main && go get
RUN go build -o bin/auth-server src/main/main.go 

# FROM scratch
# COPY --from=0 /app/bin/api /app/bin/api
CMD ["/app/bin/auth-server"]
