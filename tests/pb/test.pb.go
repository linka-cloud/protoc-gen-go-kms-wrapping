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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        (unknown)
// source: tests/pb/test.proto

package pb

import (
	_ "go.linka.cloud/protoc-gen-go-kms-wrapping"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TestData struct {
	state                      protoimpl.MessageState    `protogen:"open.v1"`
	WrappedBytes               []byte                    `protobuf:"bytes,1,opt,name=wrapped_bytes,json=wrappedBytes,proto3" json:"wrapped_bytes,omitempty"`
	RepeatedWrappedBytes       [][]byte                  `protobuf:"bytes,2,rep,name=repeated_wrapped_bytes,json=repeatedWrappedBytes,proto3" json:"repeated_wrapped_bytes,omitempty"`
	WrappedString              string                    `protobuf:"bytes,3,opt,name=wrapped_string,json=wrappedString,proto3" json:"wrapped_string,omitempty"`
	RepeatedWrappedString      []string                  `protobuf:"bytes,4,rep,name=repeated_wrapped_string,json=repeatedWrappedString,proto3" json:"repeated_wrapped_string,omitempty"`
	WrappedMessage             *TestData_Message         `protobuf:"bytes,5,opt,name=wrapped_message,json=wrappedMessage,proto3" json:"wrapped_message,omitempty"`
	RepeatedWrappedMessage     []*TestData_Message       `protobuf:"bytes,6,rep,name=repeated_wrapped_message,json=repeatedWrappedMessage,proto3" json:"repeated_wrapped_message,omitempty"`
	Int64                      int64                     `protobuf:"varint,7,opt,name=int64,proto3" json:"int64,omitempty"`
	WrappedBytesValue          *wrapperspb.BytesValue    `protobuf:"bytes,8,opt,name=wrapped_bytes_value,json=wrappedBytesValue,proto3" json:"wrapped_bytes_value,omitempty"`
	RepeatedWrappedBytesValue  []*wrapperspb.BytesValue  `protobuf:"bytes,9,rep,name=repeated_wrapped_bytes_value,json=repeatedWrappedBytesValue,proto3" json:"repeated_wrapped_bytes_value,omitempty"`
	WrappedStringValue         *wrapperspb.StringValue   `protobuf:"bytes,10,opt,name=wrapped_string_value,json=wrappedStringValue,proto3" json:"wrapped_string_value,omitempty"`
	RepeatedWrappedStringValue []*wrapperspb.StringValue `protobuf:"bytes,11,rep,name=repeated_wrapped_string_value,json=repeatedWrappedStringValue,proto3" json:"repeated_wrapped_string_value,omitempty"`
	WrappedOptionalString      *string                   `protobuf:"bytes,12,opt,name=wrapped_optional_string,json=wrappedOptionalString,proto3,oneof" json:"wrapped_optional_string,omitempty"`
	WrappedOptionalBytes       []byte                    `protobuf:"bytes,13,opt,name=wrapped_optional_bytes,json=wrappedOptionalBytes,proto3,oneof" json:"wrapped_optional_bytes,omitempty"`
	unknownFields              protoimpl.UnknownFields
	sizeCache                  protoimpl.SizeCache
}

func (x *TestData) Reset() {
	*x = TestData{}
	mi := &file_tests_pb_test_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TestData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestData) ProtoMessage() {}

func (x *TestData) ProtoReflect() protoreflect.Message {
	mi := &file_tests_pb_test_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestData.ProtoReflect.Descriptor instead.
func (*TestData) Descriptor() ([]byte, []int) {
	return file_tests_pb_test_proto_rawDescGZIP(), []int{0}
}

func (x *TestData) GetWrappedBytes() []byte {
	if x != nil {
		return x.WrappedBytes
	}
	return nil
}

func (x *TestData) GetRepeatedWrappedBytes() [][]byte {
	if x != nil {
		return x.RepeatedWrappedBytes
	}
	return nil
}

func (x *TestData) GetWrappedString() string {
	if x != nil {
		return x.WrappedString
	}
	return ""
}

func (x *TestData) GetRepeatedWrappedString() []string {
	if x != nil {
		return x.RepeatedWrappedString
	}
	return nil
}

func (x *TestData) GetWrappedMessage() *TestData_Message {
	if x != nil {
		return x.WrappedMessage
	}
	return nil
}

func (x *TestData) GetRepeatedWrappedMessage() []*TestData_Message {
	if x != nil {
		return x.RepeatedWrappedMessage
	}
	return nil
}

func (x *TestData) GetInt64() int64 {
	if x != nil {
		return x.Int64
	}
	return 0
}

func (x *TestData) GetWrappedBytesValue() *wrapperspb.BytesValue {
	if x != nil {
		return x.WrappedBytesValue
	}
	return nil
}

func (x *TestData) GetRepeatedWrappedBytesValue() []*wrapperspb.BytesValue {
	if x != nil {
		return x.RepeatedWrappedBytesValue
	}
	return nil
}

func (x *TestData) GetWrappedStringValue() *wrapperspb.StringValue {
	if x != nil {
		return x.WrappedStringValue
	}
	return nil
}

func (x *TestData) GetRepeatedWrappedStringValue() []*wrapperspb.StringValue {
	if x != nil {
		return x.RepeatedWrappedStringValue
	}
	return nil
}

func (x *TestData) GetWrappedOptionalString() string {
	if x != nil && x.WrappedOptionalString != nil {
		return *x.WrappedOptionalString
	}
	return ""
}

func (x *TestData) GetWrappedOptionalBytes() []byte {
	if x != nil {
		return x.WrappedOptionalBytes
	}
	return nil
}

type TestData_Message struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	WrappedBytes  []byte                 `protobuf:"bytes,1,opt,name=wrapped_bytes,json=wrappedBytes,proto3" json:"wrapped_bytes,omitempty"`
	WrappedString string                 `protobuf:"bytes,2,opt,name=wrapped_string,json=wrappedString,proto3" json:"wrapped_string,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TestData_Message) Reset() {
	*x = TestData_Message{}
	mi := &file_tests_pb_test_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TestData_Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestData_Message) ProtoMessage() {}

func (x *TestData_Message) ProtoReflect() protoreflect.Message {
	mi := &file_tests_pb_test_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestData_Message.ProtoReflect.Descriptor instead.
func (*TestData_Message) Descriptor() ([]byte, []int) {
	return file_tests_pb_test_proto_rawDescGZIP(), []int{0, 0}
}

func (x *TestData_Message) GetWrappedBytes() []byte {
	if x != nil {
		return x.WrappedBytes
	}
	return nil
}

func (x *TestData_Message) GetWrappedString() string {
	if x != nil {
		return x.WrappedString
	}
	return ""
}

var File_tests_pb_test_proto protoreflect.FileDescriptor

var file_tests_pb_test_proto_rawDesc = []byte{
	0x0a, 0x13, 0x74, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x70, 0x62, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x74, 0x65, 0x73, 0x74, 0x73, 0x1a, 0x1e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x77, 0x72,
	0x61, 0x70, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x99, 0x08,
	0x0a, 0x08, 0x54, 0x65, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x29, 0x0a, 0x0d, 0x77, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52, 0x0c, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64,
	0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x3a, 0x0a, 0x16, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0c, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52, 0x14, 0x72, 0x65, 0x70,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x42, 0x79, 0x74, 0x65,
	0x73, 0x12, 0x2b, 0x0a, 0x0e, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x73, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52,
	0x0d, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x3c,
	0x0a, 0x17, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70,
	0x65, 0x64, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x42,
	0x04, 0x90, 0xfa, 0x06, 0x01, 0x52, 0x15, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x57,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x40, 0x0a, 0x0f,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x73, 0x2e, 0x54, 0x65,
	0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0e,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x51,
	0x0a, 0x18, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70,
	0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x73, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x44, 0x61, 0x74,
	0x61, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x16, 0x72, 0x65, 0x70, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x05, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x12, 0x51, 0x0a, 0x13, 0x77, 0x72, 0x61, 0x70, 0x70,
	0x65, 0x64, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x73, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52, 0x11, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64,
	0x42, 0x79, 0x74, 0x65, 0x73, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x62, 0x0a, 0x1c, 0x72, 0x65,
	0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x62,
	0x79, 0x74, 0x65, 0x73, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x73, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x04, 0x90,
	0xfa, 0x06, 0x01, 0x52, 0x19, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x57, 0x72, 0x61,
	0x70, 0x70, 0x65, 0x64, 0x42, 0x79, 0x74, 0x65, 0x73, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x54,
	0x0a, 0x14, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01,
	0x52, 0x12, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x12, 0x65, 0x0a, 0x1d, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52,
	0x1a, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x41, 0x0a, 0x17, 0x77,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f,
	0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x90, 0xfa,
	0x06, 0x01, 0x48, 0x00, 0x52, 0x15, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x4f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x88, 0x01, 0x01, 0x12, 0x3f,
	0x0a, 0x16, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x04,
	0x90, 0xfa, 0x06, 0x01, 0x48, 0x01, 0x52, 0x14, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x42, 0x79, 0x74, 0x65, 0x73, 0x88, 0x01, 0x01, 0x1a,
	0x61, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x29, 0x0a, 0x0d, 0x77, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x42, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x52, 0x0c, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64,
	0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x2b, 0x0a, 0x0e, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64,
	0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x90,
	0xfa, 0x06, 0x01, 0x52, 0x0d, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x42, 0x1a, 0x0a, 0x18, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x42, 0x19,
	0x0a, 0x17, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x61, 0x6c, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x42, 0x81, 0x01, 0x0a, 0x09, 0x63, 0x6f,
	0x6d, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x73, 0x42, 0x09, 0x54, 0x65, 0x73, 0x74, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x35, 0x67, 0x6f, 0x2e, 0x6c, 0x69, 0x6e, 0x6b, 0x61, 0x2e, 0x63,
	0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d,
	0x67, 0x6f, 0x2d, 0x6b, 0x6d, 0x73, 0x2d, 0x77, 0x72, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x2f,
	0x74, 0x65, 0x73, 0x74, 0x73, 0x2f, 0x70, 0x62, 0x3b, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x54, 0x58,
	0x58, 0xaa, 0x02, 0x05, 0x54, 0x65, 0x73, 0x74, 0x73, 0xca, 0x02, 0x05, 0x54, 0x65, 0x73, 0x74,
	0x73, 0xe2, 0x02, 0x11, 0x54, 0x65, 0x73, 0x74, 0x73, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x05, 0x54, 0x65, 0x73, 0x74, 0x73, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tests_pb_test_proto_rawDescOnce sync.Once
	file_tests_pb_test_proto_rawDescData = file_tests_pb_test_proto_rawDesc
)

func file_tests_pb_test_proto_rawDescGZIP() []byte {
	file_tests_pb_test_proto_rawDescOnce.Do(func() {
		file_tests_pb_test_proto_rawDescData = protoimpl.X.CompressGZIP(file_tests_pb_test_proto_rawDescData)
	})
	return file_tests_pb_test_proto_rawDescData
}

var file_tests_pb_test_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_tests_pb_test_proto_goTypes = []any{
	(*TestData)(nil),               // 0: tests.TestData
	(*TestData_Message)(nil),       // 1: tests.TestData.Message
	(*wrapperspb.BytesValue)(nil),  // 2: google.protobuf.BytesValue
	(*wrapperspb.StringValue)(nil), // 3: google.protobuf.StringValue
}
var file_tests_pb_test_proto_depIdxs = []int32{
	1, // 0: tests.TestData.wrapped_message:type_name -> tests.TestData.Message
	1, // 1: tests.TestData.repeated_wrapped_message:type_name -> tests.TestData.Message
	2, // 2: tests.TestData.wrapped_bytes_value:type_name -> google.protobuf.BytesValue
	2, // 3: tests.TestData.repeated_wrapped_bytes_value:type_name -> google.protobuf.BytesValue
	3, // 4: tests.TestData.wrapped_string_value:type_name -> google.protobuf.StringValue
	3, // 5: tests.TestData.repeated_wrapped_string_value:type_name -> google.protobuf.StringValue
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_tests_pb_test_proto_init() }
func file_tests_pb_test_proto_init() {
	if File_tests_pb_test_proto != nil {
		return
	}
	file_tests_pb_test_proto_msgTypes[0].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_tests_pb_test_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_tests_pb_test_proto_goTypes,
		DependencyIndexes: file_tests_pb_test_proto_depIdxs,
		MessageInfos:      file_tests_pb_test_proto_msgTypes,
	}.Build()
	File_tests_pb_test_proto = out.File
	file_tests_pb_test_proto_rawDesc = nil
	file_tests_pb_test_proto_goTypes = nil
	file_tests_pb_test_proto_depIdxs = nil
}
