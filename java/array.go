package java

import (
	"strconv"
	"strings"
)

type Array struct {
	Dim        int
	Type       string
	Descriptor Descriptor
	vals       []interface{}
}

func NewEmptyArray(c *Class, dim int) *Array {
	if dim <= 0 {
		panic("error array dim :" + strconv.Itoa(dim))
	}
	return &Array{
		vals:       make([]interface{}, 0),
		Type:       c.Name,
		Dim:        dim,
		Descriptor: Descriptor(strings.Repeat("[]", dim) + c.Name),
	}
}

func (a *Array) Get(index int) interface{} {
	return a.vals[index]
}

func (a *Array) PutObject(object *Object) {
	if string(object.Descriptor) != a.Type {
		panic("error put error type element to array")
	}
	a.vals = append(a.vals, object)
}

func (a *Array) Put(val interface{}, index int) {
	a.vals[index] = val
}

func NewArrayArray(array *Array) *Array {
	return &Array{
		vals:       []interface{}{[]*Array{array}},
		Type:       array.Type,
		Dim:        array.Dim + 1,
		Descriptor: Descriptor(array.Type + strings.Repeat("[]", array.Dim+1)),
	}
}

func NewClassArray(val []Class) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "java.lang.Class",
		Dim:        1,
		Descriptor: "java.lang.Class[]",
	}
}

func NewObjectArray(val []Object) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "java.lang.Object",
		Dim:        1,
		Descriptor: "java.lang.Object[]",
	}
}

func NewByteArray(val []byte) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "byte",
		Dim:        1,
		Descriptor: "byte[]",
	}
}

func NewIntArray(val []int32) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "int",
		Dim:        1,
		Descriptor: "int[]",
	}
}
func NewFloatArray(val []float32) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "float",
		Dim:        1,
		Descriptor: "float[]",
	}
}
func NewStringArray(val []string) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "java.lang.String",
		Dim:        1,
		Descriptor: "string[]",
	}
}
func NewBoolArray(val []bool) *Array {
	return &Array{
		vals:       []interface{}{val},
		Type:       "bool",
		Dim:        1,
		Descriptor: "bool[]",
	}
}

func (a *Array) GetDescriptor() string {
	return a.Descriptor.Value()
}

func (a *Array) Length() int {
	return len(a.vals)
}

func (a *Array) Values() []interface{} {
	return a.vals
}
