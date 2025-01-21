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

package module

import (
	"fmt"
	"strings"
	"text/template"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"go.linka.cloud/protoc-gen-go-kms-wrapping/wrap"
)

var _ pgs.Module = (*Module)(nil)

func Wrap() *Module {
	return &Module{
		ModuleBase: &pgs.ModuleBase{},
		imports:    make(map[string]struct{}),
		oneOfs:     make(map[string]struct{}),
	}
}

type Module struct {
	*pgs.ModuleBase
	ctx     pgsgo.Context
	tpl     *template.Template
	imports map[string]struct{}
	oneOfs  map[string]struct{}
}

func (m *Module) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.ctx = pgsgo.InitContext(c.Parameters())
	tpl := template.New("fields").Funcs(map[string]interface{}{
		"package": m.ctx.PackageName,
		"name":    m.ctx.Name,
		"comment": func(s string) string {
			var out string
			parts := strings.Split(s, "\n")
			for i, v := range parts {
				if i == len(parts)-1 && v == "" {
					return out
				}
				out += "//" + v + "\n"
			}
			return out
		},
		"imports": func() string {
			var imports string
			for v := range m.imports {
				imports += fmt.Sprintf("\"%s\"\n", v)
			}
			return imports
		},
		"enabled": func(f pgs.Field) bool {
			var enabled bool
			ok, err := f.Extension(wrap.E_Wrap, &enabled)
			if err != nil || !ok {
				return true
			}
			return enabled
		},
		"wrap": func(f pgs.Field) string {
			v, _ := m.genFieldSeal(f)
			return v
		},
		"unwrap": func(f pgs.Field) string {
			v, _ := m.genFieldUnseal(f)
			return v
		},
	})
	m.tpl = template.Must(tpl.Parse(sealTpl))
}

func (m *Module) Execute(targets map[string]pgs.File, packages map[string]pgs.Package) []pgs.Artifact {
	for _, f := range targets {
		m.generate(f)
	}
	return m.Artifacts()
}

func (m *Module) Name() string {
	return "go-wrap"
}

func (m *Module) Check(msg pgs.Message) {
	m.Push("msg: " + msg.Name().String())
	defer m.Pop()

	for _, f := range msg.Fields() {
		m.check(f)
	}
}

func (m *Module) check(f pgs.Field) {
	m.Push("field: " + f.Name().String())
	defer m.Pop()
	var s bool
	_, err := f.Extension(wrap.E_Wrap, &s)
	m.CheckErr(err, "unable to read wrap extension from message")
	if !s {
		m.Debug("wrap not enabled for message")
		return
	}
	switch {
	case f.Type().IsMap():
		m.Fail("map fields are not supported")
	case f.Type().IsRepeated():
		t := f.Type().Element().ProtoType()
		wk := pgs.UnknownWKT
		if emb := f.Type().Element().Embed(); emb != nil {
			wk = emb.WellKnownType()
		}
		if t != pgs.BytesT && t != pgs.StringT && wk != pgs.StringValueWKT && wk != pgs.BytesValueWKT {
			m.Fail("repeated fields must be bytes or string")
		}
	default:
		t := f.Type().ProtoType()
		wk := pgs.UnknownWKT
		if emb := f.Type().Embed(); emb != nil {
			wk = emb.WellKnownType()
		}
		if t != pgs.BytesT && t != pgs.StringT && wk != pgs.StringValueWKT && wk != pgs.BytesValueWKT {
			m.Fail("field must be bytes or string")
		}
	}
}

func (m *Module) gen(f pgs.Field, revert bool) (string, bool) {
	m.Push(f.Name().String())
	defer m.Pop()
	var s bool
	if _, err := f.Extension(wrap.E_Wrap, &s); err != nil || !s && !f.Type().IsEmbed() && !(f.Type().IsRepeated() && f.Type().Element().IsEmbed()) {
		return "", false
	}
	wk := pgs.UnknownWKT
	if emb := f.Type().Embed(); emb != nil {
		wk = emb.WellKnownType()
	}
	var bfn func(string) string
	if revert {
		bfn = unwrapBytes
	} else {
		bfn = wrapBytes
	}
	var sfn func(string) string
	if revert {
		sfn = unwrapString
	} else {
		sfn = wrapString
	}
	var mfn func(string) string
	if revert {
		mfn = unwrapMessage
	} else {
		mfn = wrapMessage
	}
	if f.Type().IsRepeated() {
		if embed := f.Type().Element().Embed(); embed != nil {
			wk = embed.WellKnownType()
		}
		switch {
		case wk == pgs.BytesValueWKT:
			return loop(fmt.Sprintf("x.%s", m.ctx.Name(f)), func(s string) string {
				return wkt(s, bfn)
			}), true
		case wk == pgs.StringValueWKT:
			return loop(fmt.Sprintf("x.%s", m.ctx.Name(f)), func(s string) string {
				return wkt(s, sfn)
			}), true
		case f.Type().Element().ProtoType() == pgs.BytesT:
			return loop(fmt.Sprintf("x.%s", m.ctx.Name(f)), bfn), true
		case f.Type().Element().ProtoType() == pgs.StringT:
			return loop(fmt.Sprintf("x.%s", m.ctx.Name(f)), sfn), true
		case f.Type().Element().ProtoType() == pgs.MessageT:
			return loop(fmt.Sprintf("x.%s", m.ctx.Name(f)), mfn), true
		}
		return "", false
	}
	switch {
	case wk == pgs.BytesValueWKT:
		return wkt(fmt.Sprintf("x.%s", m.ctx.Name(f)), bfn), true
	case wk == pgs.StringValueWKT:
		return wkt(fmt.Sprintf("x.%s", m.ctx.Name(f)), sfn), true
	}
	switch f.Type().ProtoType() {
	case pgs.BytesT:
		return bfn(fmt.Sprintf("x.%s", m.ctx.Name(f))), true
	case pgs.StringT:
		if f.HasOptionalKeyword() {
			return opt(fmt.Sprintf("x.%s", m.ctx.Name(f)), sfn), true
		}
		return sfn(fmt.Sprintf("x.%s", m.ctx.Name(f))), true
	case pgs.MessageT:
		return mfn(fmt.Sprintf("x.%s", m.ctx.Name(f))), true
	}
	return "", false
}

func (m *Module) genFieldSeal(f pgs.Field) (string, bool) {
	return m.gen(f, false)
}

func (m *Module) genFieldUnseal(f pgs.Field) (string, bool) {
	return m.gen(f, true)
}

func (m *Module) generate(f pgs.File) {
	if len(f.Messages()) == 0 {
		return
	}
	for _, msg := range f.Messages() {
		m.Check(msg)
	}
	name := m.ctx.OutputPath(f).SetExt(".wrap.go")
	m.AddGeneratorTemplateFile(name.String(), m.tpl, f)
}

func wkt(r string, e func(e string) string) string {
	return fmt.Sprintf(`
if %s != nil { %s }`, r, e(fmt.Sprintf("%s.Value", r)))
}

func opt(r string, e func(s string) string) string {
	return fmt.Sprintf(`
if %s != nil { %s }`, r, e(fmt.Sprintf("*%s", r)))
}

func loop(r string, e func(s string) string) string {
	return fmt.Sprintf(`
for i := range %s { %s }`, r, e(fmt.Sprintf("%s[i]", r)))
}

func wrapMessage(r string) string {
	return fmt.Sprintf(`
if s, ok := any(%s).(Wrapper); ok {
	if err := s.Wrap(ctx, w, opts...); err != nil {
		return err
	}
}`, r)
}

func wrapString(r string) string {
	return fmt.Sprintf(`
{
	if len(%[1]s) != 0 {
		info, err := w.Encrypt(ctx, []byte(%[1]s), opts...)
		if err != nil {
			return err
		}
		b, err := proto.Marshal(info)
		if err != nil {
			return err
		}
		%[1]s = base64.RawStdEncoding.EncodeToString(b)
	}
}`, r)
}

func wrapBytes(r string) string {
	return fmt.Sprintf(`
{
	if len(%[1]s) != 0 {
		info, err := w.Encrypt(ctx, %[1]s, opts...)
		if err != nil {
			return err
		}
		%[1]s, err = proto.Marshal(info)
		if err != nil {
			return err
		}
	}
}`, r)
}

func unwrapMessage(r string) string {
	return fmt.Sprintf(`
if s, ok := any(%s).(Unwrapper); ok {
	if err := s.Unwrap(ctx, w, opts...); err != nil {
		return err
	}
}`, r)
}

func unwrapString(r string) string {
	return fmt.Sprintf(`
{
	if len(%[1]s) != 0 {
		b, err := base64.RawStdEncoding.DecodeString(%[1]s)
		if err != nil {
			return err
		}
		var info wrapping.BlobInfo
		if err := proto.Unmarshal(b, &info); err != nil {
			return err
		}
		b, err = w.Decrypt(ctx, &info, opts...)
		if err != nil {
			return err
		}
		%[1]s = string(b)
	}
}`, r)
}

func unwrapBytes(r string) string {
	return fmt.Sprintf(`
{
	if len(%[1]s) != 0 {
		var info wrapping.BlobInfo
		if err := proto.Unmarshal(%[1]s, &info); err != nil {
			return err
		}
		b, err := w.Decrypt(ctx, &info, opts...)
		if err != nil {
			return err
		}
		%[1]s = b
	}
}`, r)
}

const sealTpl = `{{ comment .SyntaxSourceCodeInfo.LeadingComments }}
{{ range .SyntaxSourceCodeInfo.LeadingDetachedComments }}
{{ comment . }}
{{ end }}
// Code generated by protoc-gen-go-kms-wrapping. DO NOT EDIT.

package {{ package . }}

import (
	"context"
	"encoding/base64"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
	{{ imports }}
)

var (
	_ = wrapping.Wrapper(nil)
	_ = context.Background()
	_ = proto.Message(nil)
	_ = base64.RawStdEncoding
)

{{ range .AllMessages }}

func (x *{{ name . }}) Wrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error {
	type Wrapper interface {
		Wrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error
	}
	{{- range .Fields }}
	    {{- if enabled . }}
			{{- wrap . }}
        {{- end }}
	{{- end }} 
	return nil
}
func (x *{{ name . }}) Unwrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error {
	type Unwrapper interface {
		Unwrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error
	}
	{{- range .Fields }}
	    {{- if enabled . }}
			{{- unwrap . }}
        {{- end }}
	{{- end }} 
	return nil
}
{{- end }}
`
