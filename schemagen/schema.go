// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	// import all the attestation types
	_ "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation"
)

var directory string

func init() {
	flag.StringVar(&directory, "dir", "schemagen", "Directory to store the generated docs")
	flag.Parse()
}

func main() {
	entries := attestation.RegistrationEntries()
	for _, entry := range entries {
		att := entry.Factory()
		schema := att.Schema()
		schemaJson, err := schema.MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}

		var indented bytes.Buffer
		err = json.Indent(&indented, schemaJson, "", "  ")
		if err != nil {
			fmt.Println("Error marshalling JSON schema:", err)
			os.Exit(1)
		}

		log.Printf("Writing schema for attestor %s to %s/%s.json", att.Name(), directory, att.Name())
		err = os.WriteFile(fmt.Sprintf("%s/%s.json", directory, att.Name()), indented.Bytes(), 0644)
		if err != nil {
			log.Fatal("Error writing to file:", err)
		}
	}
}
