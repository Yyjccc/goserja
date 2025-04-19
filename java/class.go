package java

import (
	"errors"
	"reflect"
	"strings"
)

type Class struct {
	Name             string
	Super            string
	SerialVersionUID uint64
	AccessFlags
	IsProxy        bool
	ProxyInterface []Interface
	Implements     []Interface
	Fields         []Field
	//自定义writeObject逻辑 ,用于写入字段数据
	WriteObjectData func(ser interface{}, obj *Object)
	ReadObjectData  func(ser interface{}, obj *Object) error
}

func (c *Class) SuperClass() *Class {
	if c == nil || c.Super == "" {
		return nil
	}
	return LoadClass(c.Super)
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
		_, ok = reverseTypeMap[desc]
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

func (c *Class) MustEquals(class *Class) error {
	if c.Name != class.Name {
		return errors.New("class name mismatch")
	}
	if c.SerialVersionUID != class.SerialVersionUID {
		return errors.New("class serial version UID mismatch")
	}
	if len(c.Fields) != len(class.Fields) {
		num1 := 0
		num2 := 0
		for _, f := range c.Fields {
			if !f.IsTransient() {
				num1++
			}
		}
		for _, f := range class.Fields {
			if !f.IsTransient() {
				num2++
			}
		}
		if num1 != num2 {
			return errors.New("class fields length mismatch")
		}

	}
	return nil
}

func (c *Class) IsPrimitive() bool {
	if strings.Contains(c.Name, "[") {
		if !strings.Contains(c.Name, "]") {
			return MakeDescriptor(c.Name).IsPrimitive()
		}
	}
	if _, ok := PrimitiveMap[c.Name]; ok {
		return true
	}
	if _, ok := reverseTypeMap[c.Name]; ok {
		return true
	}
	return false
}

type Jar struct {
	Classes           []Class
	Interfaces        []Interface
	Name              string
	LocationDesc      string //定位信息
	HookRegisterClass func(class *Class) Class
	Note              string
}

func (j *Jar) LoadJar(loader *ClassLoader) {
	for _, class := range j.Classes {
		if j.HookRegisterClass != nil {
			clazz := class
			hookClazz := j.HookRegisterClass(&clazz)
			loader.RegisterClass(hookClazz)
		} else {
			loader.RegisterClass(class)
		}
	}
	for _, i := range j.Interfaces {
		loader.RegisterInterface(i)
	}
	j.HookRegisterClass = nil
}

func (j *Jar) HookDefineClass(f func(class *Class) Class) *Jar {
	j.HookRegisterClass = f
	return j
}
