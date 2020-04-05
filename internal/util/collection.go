package util

// StringSet : a Set for strings
type StringSet map[string]struct{}

// NewStringSet creates a new StringSet from a number of passed string keys.
func NewStringSet(vals ...string) StringSet {
	set := make(StringSet)
	for _, val := range vals {
		set[val] = struct{}{}
	}
	return set
}

// Has tests the existence of `key` in the set.
func (set StringSet) Has(key string) bool {
	_, ok := set[key]
	return ok
}

// Add puts a value into the set.
func (set StringSet) Add(key string) StringSet {
	set[key] = struct{}{}
	return set
}

// Delete removes a value from the set.
func (set StringSet) Delete(key string) StringSet {
	delete(set, key)
	return set
}

// Values returns the contents of the set.
func (set StringSet) Values() []string {
	values := make([]string, 0)
	for k := range set {
		values = append(values, k)
	}
	return values
}

// Copy returns a copy of a set.
func (set StringSet) Copy() StringSet {
	copy := make(StringSet)
	for k, v := range set {
		copy[k] = v
	}
	return copy
}
