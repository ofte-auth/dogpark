package util

import (
	"testing"
)

func Test_StringSet(t *testing.T) {

	set := NewStringSet("foo", "bar", "baz")
	if !set.Has("foo") {
		t.Fail()
	}
	if !set.Has("bar") {
		t.Fail()
	}
	if set.Has("boofar") {
		t.Fail()
	}
	values := set.Values()
	if len(values) != 3 {
		t.Fail()
	}

	_, ok := set["bar"]
	if !ok {
		t.Fail()
	}
	_, ok = set["barfoo"]
	if ok {
		t.Fail()
	}

	set.Add("fourth").Add("fifth")
	if len(set) != 5 {
		t.Fail()
	}

	copy := set.Copy()
	copy.Add("fubar")

	if set.Has("fubar") {
		t.Fail()
	}
}
