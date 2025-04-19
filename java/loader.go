package java

import "fmt"

var bootLoader *ClassLoader

var contextClassLoader = bootLoader

func GetContextClassLoader() *ClassLoader {
	if contextClassLoader == nil {
		contextClassLoader = bootLoader
	}
	return contextClassLoader
}

func LoadClass(className string) *Class {
	if contextClassLoader == nil {
		contextClassLoader = bootLoader
	}
	return contextClassLoader.LoadClass(className)
}

func SetContextClassLoader(loader *ClassLoader) {
	contextClassLoader = loader
}

func GetPrimitiveClass(typeName string) *Class {
	if class, ok := PrimitiveMap[typeName]; ok {
		return &class
	}
	return nil
}

type ClassLoader struct {
	baseMap      map[string]Class
	interfaceMap map[string]Interface
	parent       *ClassLoader
}

func NewClassLoader(parent *ClassLoader) *ClassLoader {
	if parent == nil {
		parent = bootLoader
	}
	return &ClassLoader{
		baseMap:      make(map[string]Class),
		parent:       parent,
		interfaceMap: make(map[string]Interface),
	}
}

func (loader *ClassLoader) LoadClass(className string) *Class {
	if class, ok := loader.baseMap[className]; ok {
		return &class
	}
	if loader.parent != nil {
		return loader.parent.LoadClass(className)
	}
	return nil
}

func (loader *ClassLoader) FindInterface(interfaceName string) *Interface {
	if i, ok := loader.interfaceMap[interfaceName]; ok {
		return &i
	}
	if loader.parent != nil {
		return loader.parent.FindInterface(interfaceName)
	}
	return nil
}

func (loader *ClassLoader) RegisterClass(class Class) bool {
	loadClass := loader.LoadClass(class.Name)
	if loadClass == nil {
		loader.baseMap[class.Name] = class
		return true
	}
	loader.baseMap[class.Name] = class
	return false
}

func (loader *ClassLoader) RegisterWriteObject(f func(ser interface{}, obj *Object), className string) error {
	class := loader.LoadClass(className)
	if class == nil {
		return fmt.Errorf("class %s not exist", className)
	}
	class.WriteObjectData = f
	loader.RegisterClass(*class)
	return nil
}

func (loader *ClassLoader) RegisterInterface(i Interface) {
	loader.interfaceMap[i.Name] = i
}

func (loader *ClassLoader) RegisterReadObject(f func(ser interface{}, obj *Object) error, className string) error {
	class := loader.LoadClass(className)
	if class == nil {
		return fmt.Errorf("class %s not exist", className)
	}
	class.ReadObjectData = f
	loader.RegisterClass(*class)
	return nil
}

func ClassForName(className string) (*Class, error) {
	class := bootLoader.LoadClass(className)
	if class != nil {
		return class, nil
	}
	return nil, fmt.Errorf("class %s not found", className)
}
