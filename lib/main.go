package main

import "C"
import (
	"encoding/json"

	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/signer/file"
)

type SimplifiedRunOptions struct {
	StepName          string   `json:"step_name"`
	KeyPath           string   `json:"key_path"`
	CertPath          string   `json:"cert_path"`
	IntermediatePaths []string `json:"intermediate_paths"`
}

//export RunWrapper
func RunWrapper(optionsJson *C.char) *C.char {
	optionsStr := C.GoString(optionsJson)
	var options SimplifiedRunOptions
	err := json.Unmarshal([]byte(optionsStr), &options)
	if err != nil {
		return C.CString("Error: Invalid options JSON")
	}

	// Setup the signer
	fsp := file.New(
		file.WithKeyPath(options.KeyPath),
		file.WithCertPath(options.CertPath),
		file.WithIntermediatePaths(options.IntermediatePaths),
	)
	signer, err := fsp.Signer(nil)
	if err != nil {
		return C.CString("Error: " + err.Error())
	}

	// Call the original Run function with the signer and other options
	// Implement your logic here as needed
	// Call the witness.Run function with the options
	result, err := witness.Run(options.StepName, signer)
	if err != nil {
		return C.CString(err.Error())
	}

	// Marshal the result to JSON
	resultStr, err := json.Marshal(result)
	if err != nil {
		return C.CString(err.Error())
	}

	return C.CString(string(resultStr))
}

func main() {}
