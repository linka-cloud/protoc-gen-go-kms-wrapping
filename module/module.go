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
		"enabled": func(m pgs.Message) (bool, error) {
			var enabled bool
			_, err := m.Extension(wrap.E_Enabled, &enabled)
			if err != nil {
				return false, err
			}
			return enabled, nil
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

func (m *Module) Check(msg pgs.Message) bool {
	m.Push("msg: " + msg.Name().String())
	defer m.Pop()

	var enabled bool
	_, err := msg.Extension(wrap.E_Enabled, &enabled)
	m.CheckErr(err, "unable to read wrap extension from message")
	if !enabled {
		return false
	}
	for _, f := range msg.Fields() {
		m.check(f)
	}
	return true
}

func (m *Module) check(f pgs.Field) {
	m.Push("field: " + f.Name().String())
	defer m.Pop()
	var s bool
	_, err := f.Extension(wrap.E_Wrap, &s)
	m.CheckErr(err, "unable to read wrap extension from field")
	if !s {
		m.Debug("wrap not enabled for field")
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
		bfn = unwrapValue
	} else {
		bfn = wrapValue
	}
	var sfn func(string) string
	if revert {
		sfn = unwrapValue
	} else {
		sfn = wrapValue
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
	m.Push("file: " + f.Name().String())
	defer m.Pop()
	if len(f.Messages()) == 0 {
		return
	}
	var enabled bool
	for _, msg := range f.Messages() {
		if m.Check(msg) {
			enabled = true
		}
	}
	if !enabled {
		m.Debugf("no messages enabled, skipping")
		return
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
if err := wrap.WrapValue(ctx, w, %[1]s, opts...); err != nil {
	return err
}`, r)
}

func wrapValue(r string) string {
	return fmt.Sprintf(`
if err := wrap.WrapValue(ctx, w, &%[1]s, opts...); err != nil {
	return err
}`, r)
}

func unwrapMessage(r string) string {
	return fmt.Sprintf(`
if err := wrap.UnwrapValue(ctx, w, %[1]s, opts...); err != nil {
	return err
}`, r)
}

func unwrapValue(r string) string {
	return fmt.Sprintf(`
if err := wrap.UnwrapValue(ctx, w, &%[1]s, opts...); err != nil {
	return err
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

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	wrap "go.linka.cloud/protoc-gen-go-kms-wrapping"
	{{ imports }}
)

var (
	_ = wrapping.Wrapper(nil)
	_ = wrap.Wrapper(nil)
)

{{ range .AllMessages }}
{{- if enabled . }}
// Wrap wraps the sensitive struct fields with the provided wrapper.
func (x *{{ name . }}) Wrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error {
	{{- range .Fields }}
		{{- wrap . }}
	{{- end }} 
	return nil
}

// Unwrap unwraps the sensitive struct fields with the provided wrapper.
func (x *{{ name . }}) Unwrap(ctx context.Context, w wrapping.Wrapper, opts ...wrapping.Option) error {
	{{- range .Fields }}
		{{- unwrap . }}
	{{- end }} 
	return nil
}
{{- end }}
{{- end }}
`
