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
// source: wrap/wrap.proto

package wrap

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var file_wrap_wrap_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.MessageOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         14242,
		Name:          "go.kms.enabled",
		Tag:           "varint,14242,opt,name=enabled",
		Filename:      "wrap/wrap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         14242,
		Name:          "go.kms.wrap",
		Tag:           "varint,14242,opt,name=wrap",
		Filename:      "wrap/wrap.proto",
	},
}

// Extension fields to descriptorpb.MessageOptions.
var (
	// enabled enables the generation of KMS wrapping code for the message.
	//
	// optional bool enabled = 14242;
	E_Enabled = &file_wrap_wrap_proto_extTypes[0]
)

// Extension fields to descriptorpb.FieldOptions.
var (
	// wrap enables the wrapping of the field.
	// The field must be a string or bytes type (or well-known types equivalent) to be wrapped.
	// Message fields will be wrapped if the message implements the Wrapper interface.
	//
	// optional bool wrap = 14242;
	E_Wrap = &file_wrap_wrap_proto_extTypes[1]
)

var File_wrap_wrap_proto protoreflect.FileDescriptor

var file_wrap_wrap_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x77, 0x72, 0x61, 0x70, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x06, 0x67, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3a, 0x3d, 0x0a, 0x07, 0x65,
	0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1f, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xa2, 0x6f, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07,
	0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x88, 0x01, 0x01, 0x3a, 0x35, 0x0a, 0x04, 0x77, 0x72,
	0x61, 0x70, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x18, 0xa2, 0x6f, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x77, 0x72, 0x61, 0x70, 0x88, 0x01,
	0x01, 0x42, 0x80, 0x01, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x2e, 0x6b, 0x6d, 0x73,
	0x42, 0x09, 0x57, 0x72, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2e, 0x67,
	0x6f, 0x2e, 0x6c, 0x69, 0x6e, 0x6b, 0x61, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x67, 0x6f, 0x2d, 0x6b, 0x6d, 0x73, 0x2d,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x3b, 0x77, 0x72, 0x61, 0x70, 0xa2, 0x02, 0x03,
	0x47, 0x4b, 0x58, 0xaa, 0x02, 0x06, 0x47, 0x6f, 0x2e, 0x4b, 0x6d, 0x73, 0xca, 0x02, 0x06, 0x47,
	0x6f, 0x5c, 0x4b, 0x6d, 0x73, 0xe2, 0x02, 0x12, 0x47, 0x6f, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x47,
	0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x07, 0x47, 0x6f, 0x3a,
	0x3a, 0x4b, 0x6d, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_wrap_wrap_proto_goTypes = []any{
	(*descriptorpb.MessageOptions)(nil), // 0: google.protobuf.MessageOptions
	(*descriptorpb.FieldOptions)(nil),   // 1: google.protobuf.FieldOptions
}
var file_wrap_wrap_proto_depIdxs = []int32{
	0, // 0: go.kms.enabled:extendee -> google.protobuf.MessageOptions
	1, // 1: go.kms.wrap:extendee -> google.protobuf.FieldOptions
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	0, // [0:2] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_wrap_wrap_proto_init() }
func file_wrap_wrap_proto_init() {
	if File_wrap_wrap_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_wrap_wrap_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 2,
			NumServices:   0,
		},
		GoTypes:           file_wrap_wrap_proto_goTypes,
		DependencyIndexes: file_wrap_wrap_proto_depIdxs,
		ExtensionInfos:    file_wrap_wrap_proto_extTypes,
	}.Build()
	File_wrap_wrap_proto = out.File
	file_wrap_wrap_proto_rawDesc = nil
	file_wrap_wrap_proto_goTypes = nil
	file_wrap_wrap_proto_depIdxs = nil
}
