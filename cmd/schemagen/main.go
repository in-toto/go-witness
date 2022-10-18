package main

import (
	"fmt"
	"os"

	"github.com/invopop/jsonschema"
	"github.com/testifysec/go-witness/attestation"
	awsiid "github.com/testifysec/go-witness/attestation/aws-iid"
	"github.com/testifysec/go-witness/attestation/commandrun"
	"github.com/testifysec/go-witness/attestation/environment"
	gcpiit "github.com/testifysec/go-witness/attestation/gcp-iit"
	"github.com/testifysec/go-witness/attestation/git"
	"github.com/testifysec/go-witness/attestation/github"
	"github.com/testifysec/go-witness/attestation/gitlab"
	"github.com/testifysec/go-witness/attestation/material"
	"github.com/testifysec/go-witness/attestation/maven"
	"github.com/testifysec/go-witness/attestation/oci"
	"github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/attestation/sarif"
	"github.com/testifysec/go-witness/attestation/sbom"
	"github.com/testifysec/go-witness/attestation/scorecard"
	"github.com/testifysec/go-witness/attestation/syft"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: shemagen <schema direcotry>")
		os.Exit(1)
	}
	output_dir := os.Args[1]
	if output_dir == "" {
		output_dir = "schemas"
	}

	// Create the output directory if it doesn't exist
	if _, err := os.Stat(output_dir); os.IsNotExist(err) {
		os.Mkdir(output_dir, 0755)
	}

	// Generate the schemas
	factoryItems := []attestation.Attestor{
		&awsiid.Attestor{},
		&commandrun.CommandRun{},
		&environment.Attestor{},
		&gcpiit.Attestor{},
		&git.Attestor{},
		&github.Attestor{},
		&gitlab.Attestor{},
		&material.Attestor{},
		&maven.Attestor{},
		&oci.Attestor{},
		&product.Attestor{},
		&sarif.Attestor{},
		&sbom.Attestor{},
		&scorecard.Attestor{},
		&syft.Attestor{},
	}

	reflector := jsonschema.Reflector{
		BaseSchemaID:               "",
		Anonymous:                  false,
		AssignAnchor:               false,
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: false,
		DoNotReference:             true,
		ExpandedStruct:             true,
		IgnoredTypes:               []interface{}{},

		CommentMap: map[string]string{},
	}

	for _, item := range factoryItems {
		schema := reflector.Reflect(item)

		schema.ID = jsonschema.ID(item.Type())
		schema.Title = item.Name() + " attestation"
		schema.Description = fmt.Sprintf("%s %s type attestation", item.Name(), item.RunType().String())

		bytes, err := schema.MarshalJSON()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Write the schema to a file
		filename := fmt.Sprintf("%s/%s.json", output_dir, item.Name())
		f, err := os.Create(filename)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		defer f.Close()

		_, err = f.Write(bytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		f.Close()

	}

}
