#! /bin/bash

go run cmd/schemagen/main.go schemas

#run jq to format the json schema
for file in schemas/*.json; do
    jq . $file > $file.tmp && mv $file.tmp $file
done

json2ts -i schemas/ -o types/


