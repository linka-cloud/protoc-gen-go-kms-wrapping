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
// source: example/pb/types.proto

package pb

import (
	_ "go.linka.cloud/protoc-gen-go-kms-wrapping"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Sensitive struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Value         string                 `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Sensitive) Reset() {
	*x = Sensitive{}
	mi := &file_example_pb_types_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Sensitive) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sensitive) ProtoMessage() {}

func (x *Sensitive) ProtoReflect() protoreflect.Message {
	mi := &file_example_pb_types_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sensitive.ProtoReflect.Descriptor instead.
func (*Sensitive) Descriptor() ([]byte, []int) {
	return file_example_pb_types_proto_rawDescGZIP(), []int{0}
}

func (x *Sensitive) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

var File_example_pb_types_proto protoreflect.FileDescriptor

var file_example_pb_types_proto_rawDesc = []byte{
	0x0a, 0x16, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x62, 0x2f, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x74, 0x79, 0x70, 0x65, 0x73, 0x1a,
	0x0f, 0x77, 0x72, 0x61, 0x70, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x2d, 0x0a, 0x09, 0x53, 0x65, 0x6e, 0x73, 0x69, 0x74, 0x69, 0x76, 0x65, 0x12, 0x1a, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0x90, 0xfa,
	0x06, 0x01, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x04, 0x90, 0xfa, 0x06, 0x01, 0x42,
	0x84, 0x01, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x42, 0x0a, 0x54,
	0x79, 0x70, 0x65, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x37, 0x67, 0x6f, 0x2e,
	0x6c, 0x69, 0x6e, 0x6b, 0x61, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x67, 0x6f, 0x2d, 0x6b, 0x6d, 0x73, 0x2d, 0x77, 0x72,
	0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70,
	0x62, 0x3b, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x54, 0x58, 0x58, 0xaa, 0x02, 0x05, 0x54, 0x79, 0x70,
	0x65, 0x73, 0xca, 0x02, 0x05, 0x54, 0x79, 0x70, 0x65, 0x73, 0xe2, 0x02, 0x11, 0x54, 0x79, 0x70,
	0x65, 0x73, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02,
	0x05, 0x54, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_example_pb_types_proto_rawDescOnce sync.Once
	file_example_pb_types_proto_rawDescData = file_example_pb_types_proto_rawDesc
)

func file_example_pb_types_proto_rawDescGZIP() []byte {
	file_example_pb_types_proto_rawDescOnce.Do(func() {
		file_example_pb_types_proto_rawDescData = protoimpl.X.CompressGZIP(file_example_pb_types_proto_rawDescData)
	})
	return file_example_pb_types_proto_rawDescData
}

var file_example_pb_types_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_example_pb_types_proto_goTypes = []any{
	(*Sensitive)(nil), // 0: types.Sensitive
}
var file_example_pb_types_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_example_pb_types_proto_init() }
func file_example_pb_types_proto_init() {
	if File_example_pb_types_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_example_pb_types_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_example_pb_types_proto_goTypes,
		DependencyIndexes: file_example_pb_types_proto_depIdxs,
		MessageInfos:      file_example_pb_types_proto_msgTypes,
	}.Build()
	File_example_pb_types_proto = out.File
	file_example_pb_types_proto_rawDesc = nil
	file_example_pb_types_proto_goTypes = nil
	file_example_pb_types_proto_depIdxs = nil
}
