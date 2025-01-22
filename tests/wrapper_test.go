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

package tests

import (
	"context"
	"crypto/rand"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	wrap "go.linka.cloud/protoc-gen-go-kms-wrapping"
	"go.linka.cloud/protoc-gen-go-kms-wrapping/tests/pb"
)

func wrapper(t *testing.T, ctx context.Context, id string) wrapping.Wrapper {
	w := aead.NewWrapper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	_, err = w.SetConfig(ctx, wrapping.WithKeyId(id), aead.WithKey(k))
	require.NoError(t, err)
	return w
}

func TestWrap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root := wrapper(t, ctx, "root")

	m := &pb.TestData{
		WrappedBytes:          []byte("bytes"),
		RepeatedWrappedBytes:  [][]byte{[]byte("bytes"), []byte("bytes")},
		WrappedString:         "string",
		RepeatedWrappedString: []string{"string", "string"},
		WrappedMessage: &pb.TestData_Message{
			WrappedBytes:  []byte("bytes"),
			WrappedString: "string",
		},
		RepeatedWrappedMessage: []*pb.TestData_Message{
			{
				WrappedBytes:  []byte("bytes"),
				WrappedString: "string",
			},
		},
		Int64:                      42,
		WrappedBytesValue:          wrapperspb.Bytes([]byte("bytes")),
		RepeatedWrappedBytesValue:  []*wrapperspb.BytesValue{wrapperspb.Bytes([]byte("bytes")), wrapperspb.Bytes([]byte("bytes"))},
		WrappedStringValue:         wrapperspb.String("string"),
		RepeatedWrappedStringValue: []*wrapperspb.StringValue{wrapperspb.String("string"), wrapperspb.String("string")},
	}

	tests := []struct {
		name   string
		wrap   func(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error
		unwrap func(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error
	}{
		{
			name: "gen",
			wrap: func(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error {
				return m.(wrap.Wrapper).Wrap(ctx, w, opts...)
			},
			unwrap: func(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error {
				return m.(wrap.Wrapper).Unwrap(ctx, w, opts...)
			},
		},
		{
			name:   "reflect",
			wrap:   wrap.Wrap,
			unwrap: wrap.Unwrap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m2 := proto.Clone(m).(*pb.TestData)
			require.NoError(t, tt.wrap(ctx, root, m2, wrapping.WithKeyId("root")))

			assert.NotEqual(t, m.WrappedBytes, m2.WrappedBytes)
			assert.True(t, len(m2.WrappedBytes) > len(m.WrappedBytes))
			assert.NotEqual(t, m.RepeatedWrappedBytes, m2.RepeatedWrappedBytes)
			for i := range m2.RepeatedWrappedBytes {
				assert.True(t, len(m2.RepeatedWrappedBytes[i]) > len(m.RepeatedWrappedBytes[i]))
			}
			assert.NotEqual(t, m.WrappedString, m2.WrappedString)
			assert.NotEqual(t, m.RepeatedWrappedString, m2.RepeatedWrappedString)
			for i := range m2.RepeatedWrappedString {
				assert.True(t, len(m2.RepeatedWrappedString[i]) > len(m.RepeatedWrappedString[i]))
			}
			assert.NotEqual(t, m.WrappedMessage.String(), m2.WrappedMessage.String())
			assert.True(t, len(m2.WrappedMessage.String()) > len(m.WrappedMessage.String()))
			for _, v := range m.RepeatedWrappedMessage {
				assert.NotEqual(t, v.String(), m2.WrappedMessage.String())
			}

			assert.NotEqual(t, m.WrappedBytesValue, m2.WrappedBytesValue)
			assert.True(t, len(m2.WrappedBytesValue.Value) > len(m.WrappedBytesValue.Value))
			assert.NotEqual(t, m.RepeatedWrappedBytesValue, m2.RepeatedWrappedBytesValue)
			for i := range m2.RepeatedWrappedBytesValue {
				assert.True(t, len(m2.RepeatedWrappedBytesValue[i].Value) > len(m.RepeatedWrappedBytesValue[i].Value))
			}
			assert.NotEqual(t, m.WrappedStringValue, m2.WrappedStringValue)
			assert.NotEqual(t, m.RepeatedWrappedStringValue, m2.RepeatedWrappedStringValue)
			for i := range m2.RepeatedWrappedStringValue {
				assert.True(t, len(m2.RepeatedWrappedStringValue[i].Value) > len(m.RepeatedWrappedStringValue[i].Value))
			}

			other := wrapper(t, ctx, "other")
			require.Error(t, tt.unwrap(ctx, other, m2, wrapping.WithKeyId("other")))

			require.NoError(t, tt.unwrap(ctx, root, m2, wrapping.WithKeyId("root")))
			require.Equal(t, m.String(), m2.String())
		})
	}

}

func TestWrapEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root := wrapper(t, ctx, "root")
	var m pb.TestData
	m2 := proto.Clone(&m).(*pb.TestData)
	require.NoError(t, wrap.Wrap(ctx, root, m2, wrapping.WithKeyId("root")))
	require.Equal(t, m.String(), m2.String())

	require.NoError(t, wrap.Unwrap(ctx, root, m2, wrapping.WithKeyId("root")))
	require.Equal(t, m.String(), m2.String())
}

func TestWrapDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root := wrapper(t, ctx, "root")
	m := &pb.Noop{
		Value: "value",
	}
	m2 := proto.Clone(m).(*pb.Noop)
	require.NoError(t, wrap.Wrap(ctx, root, m2, wrapping.WithKeyId("root")))
	require.Equal(t, m.String(), m2.String())
}
