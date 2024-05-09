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
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/in-toto/go-witness/attestation"
	// this feels like an annoying way of importing them as it will need edited for each attestor added
	_ "github.com/in-toto/go-witness/attestation/aws-iid"
	_ "github.com/in-toto/go-witness/attestation/commandrun"
	_ "github.com/in-toto/go-witness/attestation/environment"
	_ "github.com/in-toto/go-witness/attestation/gcp-iit"
	_ "github.com/in-toto/go-witness/attestation/git"
	_ "github.com/in-toto/go-witness/attestation/github"
	_ "github.com/in-toto/go-witness/attestation/gitlab"
	_ "github.com/in-toto/go-witness/attestation/jwt"
	_ "github.com/in-toto/go-witness/attestation/link"
	_ "github.com/in-toto/go-witness/attestation/material"
	_ "github.com/in-toto/go-witness/attestation/maven"
	_ "github.com/in-toto/go-witness/attestation/oci"
	_ "github.com/in-toto/go-witness/attestation/product"
	_ "github.com/in-toto/go-witness/attestation/sarif"
	_ "github.com/in-toto/go-witness/attestation/slsa"
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
		json, err := schema.MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Writing schema for attestor %s to %s/%s.json", att.Name(), directory, att.Name())
		err = os.WriteFile(fmt.Sprintf("%s/%s.json", directory, att.Name()), json, 0644)
		if err != nil {
			log.Fatal("Error writing to file:", err)
		}
	}
}
