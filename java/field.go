package java

type Field struct {
	AccessFlags
	Descriptor   string
	DefaultValue *Object
	Name         string
}

func (f *Field) IsPrimitive() bool {
	return Descriptor(f.Descriptor).IsPrimitive()
}

func (f *Field) GetDescriptor() string {
	return Descriptor(f.Descriptor).Value()
}

func (f *Field) name() {
}

func (f *Field) GetClass() *Class {
	return bootLoader.LoadClass(string(f.Descriptor))
}

func (f *Field) Set(obj Object, value interface{}) {
	obj.Fields[f.Name] = value
}

func (f *Field) Get(obj Object) interface{} {
	return obj.Fields[f.Name]
}
