package java

type Object struct {
	clazz      *Class
	Descriptor Descriptor
	IsProxy    bool
	Fields     map[string]interface{}
	Extend     interface{} //扩展
}

func (c *Object) GetFieldDescriptor(fieldName string) *Descriptor {
	if c.clazz == nil {
		return nil
	}
	for _, field := range c.clazz.Fields {
		if field.Name == fieldName {
			descriptor := Descriptor(field.Descriptor)
			return &descriptor
		}
	}
	return nil
}

func (o *Object) GetClass() *Class {
	return o.clazz
}

func NewInstance(class Class) Object {
	return class.newInstance(nil)
}

//对基本类型进行包装

func NewString(str string) Object {
	object := Object{
		clazz:      &StringClass,
		Descriptor: StringType,
		//WriteObject: nil,
		Fields: make(map[string]interface{}),
		Extend: nil,
	}
	object.Fields["val"] = str
	return object
}

/*
基本数据类型
*/
func NewInt(val int32) Object {
	object := Object{
		clazz:      &IntegerClass,
		Descriptor: "int",
		Fields:     make(map[string]interface{}),
		Extend:     nil,
	}
	object.Fields["val"] = val
	return object
}

func NewFloat(val float32) Object {
	object := Object{

		Descriptor: "float",
		Fields:     make(map[string]interface{}),
		Extend:     nil,
	}
	object.Fields["val"] = val
	return object
}

func NewBool(val bool) Object {
	object := Object{}
	object.Fields["val"] = val
	return object
}

func (o Object) UnWrap() interface{} {
	descriptor := o.Descriptor
	if descriptor == "java.lang.String" || o.Descriptor.IsPrimitive() {
		return o.Fields["val"]
	}
	return o
}

func (c *Object) SuperClass() *Class {
	if c.clazz == nil {
		return nil
	}
	if c.clazz.Super == "" {
		return nil
	}
	return LoadClass(c.clazz.Super)
}

func MakeObject(data interface{}) *Object {

	return &Object{}
}
