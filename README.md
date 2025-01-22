# protoc-gen-go-kms-wrapping

`protoc-gen-go-kms-wrapping` is a protoc plugin that generates Go code for wrapping and unwrapping sensitive data using a Key Management Service (KMS).

It also provides a protobuf reflection-based API for wrapping and unwrapping sensitive data.

The generated code uses the [`github.com/hashicorp/go-kms-wrapping/v2`](https://github.com/hashicorp/go-kms-wrapping/v2) library.

## Installation

To install the plugin, run the following command:

```sh
go install go.linka.cloud/protoc-gen-go-kms-wrapping/cmd/protoc-gen-go-kms-wrapping@latest
```

## Usage

The main example is located in the `example/main.go` file. 
It demonstrates how to configure a KMS wrapper, generate a random key, and wrap/unwrap sensitive data.

### Protobuf Definition

The `Sensitive` message used in the example is defined in a protobuf file. Here is an example of what the protobuf definition might look like:

```proto
syntax = "proto3";

package types;

option go_package = "go.linka.cloud/protoc-gen-go-kms-wrapping/example/pb;pb";

import "wrap/wrap.proto";

message Sensitive {
  option(go.kms.enabled) = true;
  string value = 1 [(go.kms.wrap) = true];
}
```

Here is a brief overview of the example code:

#### main.go

```go
package main

import (
	"context"
	"crypto/rand"
	"log"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"

	"go.linka.cloud/protoc-gen-go-kms-wrapping"
	"go.linka.cloud/protoc-gen-go-kms-wrapping/example/pb"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wrapper := aead.NewWrapper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatalf("failed to generate random key: %v", err)
	}
	if _, err := wrapper.SetConfig(ctx, wrapping.WithKeyId("root-key"), aead.WithKey(k)); err != nil {
		log.Fatalf("failed to configure kms: %v", err)
	}

	s := &pb.Sensitive{Value: "secret"}

	// using generated code
	if err := s.Wrap(ctx, wrapper); err != nil {
		log.Fatalf("failed to wrap sensitive data: %v", err)
	}
	log.Printf("wrapped sensitive data: '%v'", s)
	if err := s.Unwrap(ctx, wrapper); err != nil {
		log.Fatalf("failed to unwrap sensitive data: %v", err)
	}
	log.Printf("unwrapped sensitive data: '%v'", s)

	// using protobuf reflection
	if err := wrap.Wrap(ctx, wrapper, s); err != nil {
		log.Fatalf("failed to wrap sensitive data: %v", err)
	}
	log.Printf("wrapped sensitive data: '%v'", s)
	if err := wrap.Unwrap(ctx, wrapper, s); err != nil {
		log.Fatalf("failed to unwrap sensitive data: %v", err)
	}
	log.Printf("unwrapped sensitive data: '%v'", s)
}
```

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
