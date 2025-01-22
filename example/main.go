// Copyright 2025 Linka Cloud  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
