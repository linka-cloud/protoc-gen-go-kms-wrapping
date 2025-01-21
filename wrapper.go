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

package wrap

import (
	"context"
	"encoding/base64"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.linka.cloud/protoc-gen-go-kms-wrapping/wrap"
)

type Wrapper interface {
	Wrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error
	Unwrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error
}

func Wrap(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error {
	if m == nil {
		return nil
	}
	msg := m.ProtoReflect()
	fields := msg.Type().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		val := msg.Get(field)
		if field.IsMap() {
			continue
		}
		if !val.IsValid() {
			continue
		}
		s := proto.GetExtension(field.Options(), wrap.E_Wrap)
		if s == nil {
			return nil
		}
		seal := s.(bool)
		var wkt bool
		if field.Kind() == protoreflect.MessageKind && (field.Message().FullName() == "google.protobuf.StringValue" || field.Message().FullName() == "google.protobuf.BytesValue") {
			wkt = true
		}
		if field.IsList() {
			l := val.List()
			if field.Kind() == protoreflect.MessageKind && !wkt {
				for i := 0; i < l.Len(); i++ {
					if err := Wrap(ctx, w, l.Get(i).Message().Interface(), opts...); err != nil {
						return err
					}
				}
				continue
			}
			if !seal {
				continue
			}
			for i := 0; i < l.Len(); i++ {
				if err := sealField(ctx, w, msg, field, i, opts...); err != nil {
					return err
				}
			}
			continue
		}
		if field.Kind() == protoreflect.MessageKind && !wkt {
			if err := Wrap(ctx, w, val.Message().Interface(), opts...); err != nil {
				return err
			}
			continue
		}
		if !seal {
			continue
		}
		if err := sealField(ctx, w, msg, field, -1, opts...); err != nil {
			return err
		}
	}
	return nil
}

func Unwrap(ctx context.Context, w wrapping.Wrapper, m proto.Message, opts ...wrapping.Option) error {
	if m == nil {
		return nil
	}
	msg := m.ProtoReflect()
	fields := msg.Type().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		val := m.ProtoReflect().Get(field)
		if field.IsMap() {
			continue
		}
		if !val.IsValid() {
			continue
		}
		s := proto.GetExtension(field.Options(), wrap.E_Wrap)
		if s == nil {
			return nil
		}
		seal := s.(bool)
		var wkt bool
		if field.Kind() == protoreflect.MessageKind && (field.Message().FullName() == "google.protobuf.StringValue" || field.Message().FullName() == "google.protobuf.BytesValue") {
			wkt = true
		}
		if field.IsList() {
			l := val.List()
			if field.Kind() == protoreflect.MessageKind && !wkt {
				for i := 0; i < l.Len(); i++ {
					if err := Unwrap(ctx, w, l.Get(i).Message().Interface(), opts...); err != nil {
						return err
					}
				}
				continue
			}
			if !seal {
				continue
			}
			for i := 0; i < l.Len(); i++ {
				if err := unsealField(ctx, w, msg, field, i, opts...); err != nil {
					return err
				}
			}
			continue
		}
		if field.Kind() == protoreflect.MessageKind && !wkt {
			if err := Unwrap(ctx, w, val.Message().Interface(), opts...); err != nil {
				return err
			}
			continue
		}
		if !seal {
			continue
		}
		if err := unsealField(ctx, w, msg, field, -1, opts...); err != nil {
			return err
		}
	}
	return nil
}

func sealField(ctx context.Context, w wrapping.Wrapper, m protoreflect.Message, f protoreflect.FieldDescriptor, idx int, opts ...wrapping.Option) error {
	if f.Kind() == protoreflect.MessageKind {
		m = get(m, f, idx).Message()
		f = f.Message().Fields().ByNumber(1)
		idx = -1
	}
	switch f.Kind() {
	case protoreflect.StringKind:
		v := get(m, f, idx).String()
		if v == "" {
			return nil
		}
		if err := seal(ctx, w, &v, opts...); err != nil {
			return err
		}
		set(m, f, idx, protoreflect.ValueOfString(v))
		return nil
	case protoreflect.BytesKind:
		v := get(m, f, idx).Bytes()
		if len(v) == 0 {
			return nil
		}
		if err := seal(ctx, w, &v, opts...); err != nil {
			return err
		}
		set(m, f, idx, protoreflect.ValueOfBytes(v))
		return nil
	default:
		return fmt.Errorf("%s: unsupported type %s", f.FullName(), f.Kind())
	}
}

func seal[T string | []byte](ctx context.Context, w wrapping.Wrapper, m *T, opts ...wrapping.Option) error {
	if m == nil || len(*m) == 0 {
		return nil
	}
	switch m := any(m).(type) {
	case *string:
		i, err := w.Encrypt(ctx, []byte(*m), opts...)
		if err != nil {
			return err
		}
		b, err := proto.Marshal(i)
		if err != nil {
			return err
		}
		*m = base64.RawStdEncoding.EncodeToString(b)
	case *[]byte:
		i, err := w.Encrypt(ctx, *m, opts...)
		if err != nil {
			return err
		}
		b, err := proto.Marshal(i)
		if err != nil {
			return err
		}
		*m = b
	}
	return nil
}

func unsealField(ctx context.Context, w wrapping.Wrapper, m protoreflect.Message, f protoreflect.FieldDescriptor, idx int, opts ...wrapping.Option) error {
	if f.Kind() == protoreflect.MessageKind {
		m = get(m, f, idx).Message()
		f = f.Message().Fields().ByNumber(1)
		idx = -1
	}
	switch f.Kind() {
	case protoreflect.StringKind:
		v := get(m, f, idx).String()
		if v == "" {
			return nil
		}
		if err := unseal(ctx, w, &v, opts...); err != nil {
			return err
		}
		set(m, f, idx, protoreflect.ValueOfString(v))
		return nil
	case protoreflect.BytesKind:
		v := get(m, f, idx).Bytes()
		if len(v) == 0 {
			return nil
		}
		if err := unseal(ctx, w, &v, opts...); err != nil {
			return err
		}
		set(m, f, idx, protoreflect.ValueOfBytes(v))
		return nil
	default:
		return fmt.Errorf("%s: unsupported type %s", f.FullName(), f.Kind())
	}
}

func unseal[T string | []byte](ctx context.Context, w wrapping.Wrapper, m *T, opts ...wrapping.Option) error {
	if m == nil || len(*m) == 0 {
		return nil
	}
	switch m := any(m).(type) {
	case *string:
		b, err := base64.RawStdEncoding.DecodeString(*m)
		if err != nil {
			return err
		}
		var i wrapping.BlobInfo
		if err := proto.Unmarshal(b, &i); err != nil {
			return err
		}
		b, err = w.Decrypt(ctx, &i, opts...)
		if err != nil {
			return err
		}
		*m = string(b)
	case *[]byte:
		var i wrapping.BlobInfo
		var err error
		if err = proto.Unmarshal(*m, &i); err != nil {
			return err
		}
		*m, err = w.Decrypt(ctx, &i, opts...)
		if err != nil {
			return err
		}
	}
	return nil
}

func get(m protoreflect.Message, f protoreflect.FieldDescriptor, idx int) protoreflect.Value {
	if idx >= 0 {
		return m.Get(f).List().Get(idx)
	}
	return m.Get(f)
}

func set(m protoreflect.Message, f protoreflect.FieldDescriptor, idx int, v protoreflect.Value) {
	if idx >= 0 {
		m.Get(f).List().Set(idx, v)
	} else {
		m.Set(f, v)
	}
}
