package java

import (
	"reflect"
	"strings"
)

type Class struct {
	Name             string
	Super            string
	ClassPath        string
	SerialVersionUID uint64
	AccessFlags
	Implements []Interface
	Fields     []Field
	//自定义writeObject逻辑 ,用于写入字段数据
	WriteObjectData func(ser interface{}, obj *Object)
	ReadObjectData  func(ser interface{}, obj *Object)
}

func (c *Class) IsAssignableFrom(fullClassName string) bool {
	for _, impl := range c.Implements {
		if impl.Name == fullClassName {
			return true
		}
	}
	if c.Super == "" {
		return false
	}
	superClass := GetContextClassLoader().LoadClass(c.Super)
	if superClass == nil {
		return false
	}
	return superClass.IsAssignableFrom(fullClassName)
}

type Interface struct {
	Name string
}

// ComputerFlag 计算序列化类信息中的flag
/**
if (externalizable) {
	flags |= ObjectStreamConstants.SC_EXTERNALIZABLE;
	int protocol = out.getProtocolVersion();
	if (protocol != ObjectStreamConstants.PROTOCOL_VERSION_1) {
	flags |= ObjectStreamConstants.SC_BLOCK_DATA;
}
} else if (serializable) {
flags |= ObjectStreamConstants.SC_SERIALIZABLE;
}
if (hasWriteObjectData) {
flags |= ObjectStreamConstants.SC_WRITE_METHOD;
}
if (isEnum) {
flags |= ObjectStreamConstants.SC_ENUM;
}
*/
func (c *Class) ComputerFlag() byte {
	if c.WriteObjectData != nil {
		return 0x03
	}
	return 0x02
}

// GetSerialVersionUID 获取序列化UID
func (c *Class) GetSerialVersionUID() uint64 {
	if c.SerialVersionUID == 0 {
		return GetSerUIDbyName(c.Name)
	}
	return c.SerialVersionUID
}

func (c *Class) NewInstance(loader *ClassLoader) Object {
	return c.newInstance(loader)
}

func (c *Class) newInstance(loader *ClassLoader) Object {
	obj := Object{
		clazz:  c,
		Fields: make(map[string]interface{}),
	}
	if loader == nil {
		loader = bootLoader
	}
	//调用父类构造方法
	if c.Super != "" {
		superClass := loader.LoadClass(c.Super)
		super := superClass.NewInstance(loader)
		for name, val := range super.Fields {
			obj.Fields[name] = val
		}
	}
	for _, field := range c.Fields {
		//obj.Fields[field.Name] = NULL
		//
		if field.DefaultValue != nil {
			obj.Fields[field.Name] = field.DefaultValue
			continue
		}
		_, ok := typeMap[field.Descriptor]

		if ok {
			obj.Fields[field.Name] = initBaseTypeValue(field.Descriptor)
			continue
		}
		//除去数组描述
		desc := strings.ReplaceAll(field.Descriptor, "[]", "")
		_, ok = typeMap[getBaseType(desc)]
		if ok {
			obj.Fields[field.Name] = initBaseTypeArrayValue(field.Descriptor)
			continue
		}
		if strings.Contains(field.Descriptor, "[]") {
			obj.Fields[field.Name] = initArrayValue(field.Descriptor)
			continue
		}
		class := field.GetClass()
		if class == nil {
			obj.Fields[field.Name] = nil
		} else {
			obj.Fields[field.Name] = class.newInstance(loader)
		}

	}
	return obj
}

func initArrayValue(descriptor string) interface{} {
	arrayDim := 0
	// 统计数组维度，并去掉 "[]" 部分
	for strings.HasSuffix(descriptor, "[]") {
		arrayDim++
		descriptor = strings.TrimSuffix(descriptor, "[]")
	}
	//class, err := ClassForName(descriptor)
	//if err != nil {
	//	panic(err)
	//}
	//value := class.newInstance()
	// 动态创建数组
	//arrayType := reflect.TypeOf(value)
	if arrayDim == 1 {
		return []Object{}
	}
	if arrayDim == 2 {
		return [][]Object{[]Object{}}
	}

	panic("unsupported array descriptor: " + descriptor)
}

func initBaseTypeArrayValue(descriptor string) interface{} {
	arrayDim := 0
	// 统计数组维度，并去掉 "[]" 部分
	for strings.HasSuffix(descriptor, "[]") {
		arrayDim++
		descriptor = strings.TrimSuffix(descriptor, "[]")
	}
	value := initBaseTypeValue(descriptor)
	// 动态创建数组
	arrayType := reflect.TypeOf(value)
	for i := 0; i < arrayDim; i++ {
		arrayType = reflect.SliceOf(arrayType)
	}

	// 创建并返回对应类型的零值数组
	return reflect.New(arrayType).Elem().Interface()
}

func (c *Class) newInstanceArray() []Object {
	objs := make([]Object, 1)
	instance := c.newInstance(nil)
	objs = append(objs, instance)
	return objs
}

func (c *Class) isAssign(javaType string) bool {
	if c.Name == javaType {
		return true
	}
	if c.Super != "" {
		superClazz, err := ClassForName(c.Super)
		if err != nil {
			return false
		}
		assign := superClazz.isAssign(javaType)
		if assign {
			return true
		}
	}
	if c.Implements != nil {
		for _, i := range c.Implements {
			if i.Name == javaType {
				return true
			}
		}
	}
	return false
}

type Jar struct {
	Classes      []Class
	Interfaces   []Interface
	Name         string
	LocationDesc string //定位信息
	Note         string
}

func (j *Jar) LoadJar(loader *ClassLoader) {
	for _, class := range j.Classes {
		loader.RegisterClass(class)
	}
	for _, i := range j.Interfaces {
		loader.RegisterInterface(i)
	}
}
