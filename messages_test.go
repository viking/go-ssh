// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

var intLengthTests = []struct {
	val, length int
}{
	{0, 4 + 0},
	{1, 4 + 1},
	{127, 4 + 1},
	{128, 4 + 2},
	{-1, 4 + 1},
}

func TestIntLength(t *testing.T) {
	for _, test := range intLengthTests {
		v := new(big.Int).SetInt64(int64(test.val))
		length := intLength(v)
		if length != test.length {
			t.Errorf("For %d, got length %d but expected %d", test.val, length, test.length)
		}
	}
}

var messageTypes = []interface{}{
	&KexInitMsg{},
	&KexDHInitMsg{},
	&ServiceRequestMsg{},
	&ServiceAcceptMsg{},
	&UserAuthRequestMsg{},
	&ChannelOpenMsg{},
	&ChannelOpenConfirmMsg{},
	&ChannelOpenFailureMsg{},
	&ChannelRequestMsg{},
	&ChannelRequestSuccessMsg{},
}

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(0))
	for i, iface := range messageTypes {
		ty := reflect.ValueOf(iface).Type()

		n := 100
		if testing.Short() {
			n = 5
		}
		for j := 0; j < n; j++ {
			v, ok := quick.Value(ty, rand)
			if !ok {
				t.Errorf("#%d: failed to create value", i)
				break
			}

			m1 := v.Elem().Interface()
			m2 := iface

			marshaled := MarshalMsg(MsgIgnore, m1)
			if err := unmarshal(m2, marshaled, MsgIgnore); err != nil {
				t.Errorf("#%d failed to unmarshal %#v: %s", i, m1, err)
				break
			}

			if !reflect.DeepEqual(v.Interface(), m2) {
				t.Errorf("#%d\ngot: %#v\nwant:%#v\n%x", i, m2, m1, marshaled)
				break
			}
		}
	}
}

func randomBytes(out []byte, rand *rand.Rand) {
	for i := 0; i < len(out); i++ {
		out[i] = byte(rand.Int31())
	}
}

func randomNameList(rand *rand.Rand) []string {
	ret := make([]string, rand.Int31()&15)
	for i := range ret {
		s := make([]byte, 1+(rand.Int31()&15))
		for j := range s {
			s[j] = 'a' + uint8(rand.Int31()&15)
		}
		ret[i] = string(s)
	}
	return ret
}

func randomInt(rand *rand.Rand) *big.Int {
	return new(big.Int).SetInt64(int64(int32(rand.Uint32())))
}

func (*KexInitMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	ki := &KexInitMsg{}
	randomBytes(ki.Cookie[:], rand)
	ki.KexAlgos = randomNameList(rand)
	ki.ServerHostKeyAlgos = randomNameList(rand)
	ki.CiphersClientServer = randomNameList(rand)
	ki.CiphersServerClient = randomNameList(rand)
	ki.MACsClientServer = randomNameList(rand)
	ki.MACsServerClient = randomNameList(rand)
	ki.CompressionClientServer = randomNameList(rand)
	ki.CompressionServerClient = randomNameList(rand)
	ki.LanguagesClientServer = randomNameList(rand)
	ki.LanguagesServerClient = randomNameList(rand)
	if rand.Int31()&1 == 1 {
		ki.FirstKexFollows = true
	}
	return reflect.ValueOf(ki)
}

func (*KexDHInitMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	dhi := &KexDHInitMsg{}
	dhi.X = randomInt(rand)
	return reflect.ValueOf(dhi)
}

// TODO(dfc) maybe this can be removed in the future if testing/quick can handle
// derived basic types.
func (RejectionReason) Generate(rand *rand.Rand, size int) reflect.Value {
	m := RejectionReason(Prohibited)
	return reflect.ValueOf(m)
}

var (
	_KexInitMsg   = new(KexInitMsg).Generate(rand.New(rand.NewSource(0)), 10).Elem().Interface()
	_KexDHInitMsg = new(KexDHInitMsg).Generate(rand.New(rand.NewSource(0)), 10).Elem().Interface()

	_kexInit   = MarshalMsg(MsgKexInit, _KexInitMsg)
	_kexDHInit = MarshalMsg(MsgKexDHInit, _KexDHInitMsg)
)

func BenchmarkMarshalKexInitMsg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		MarshalMsg(MsgKexInit, _KexInitMsg)
	}
}

func BenchmarkUnmarshalKexInitMsg(b *testing.B) {
	m := new(KexInitMsg)
	for i := 0; i < b.N; i++ {
		unmarshal(m, _kexInit, MsgKexInit)
	}
}

func BenchmarkMarshalKexDHInitMsg(b *testing.B) {
	for i := 0; i < b.N; i++ {
		MarshalMsg(MsgKexDHInit, _KexDHInitMsg)
	}
}

func BenchmarkUnmarshalKexDHInitMsg(b *testing.B) {
	m := new(KexDHInitMsg)
	for i := 0; i < b.N; i++ {
		unmarshal(m, _kexDHInit, MsgKexDHInit)
	}
}
