#! /bin/bash

go run cmd/schemagen/main.go schemas
json2ts -i schemas/ -o types/
