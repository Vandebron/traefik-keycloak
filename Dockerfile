# TODO we could probably build the jar in this file, but its to much work for
# now
FROM python:3.12-slim

WORKDIR /plugins/authenticator

COPY . .
