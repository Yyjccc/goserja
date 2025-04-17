package java

import "fmt"

var bootLoader *ClassLoader

func init() {
	bootLoader = &ClassLoader{
		baseMap: map[string]Class{
			StringClass.Name:                      StringClass,
			ObjectArrayClass.Name:                 ObjectArrayClass,
			ClassLoaderClass.Name:                 ClassLoaderClass,
			ClassClass.Name:                       ClassClass,
			ClassArrayClass.Name:                  ClassArrayClass,
			ObjectClass.Name:                      ObjectClass,
			ProxyClass.Name:                       ProxyClass,
			HashMapClass.Name:                     HashMapClass,
			AbstractMapClass.Name:                 AbstractMapClass,
			NumberClass.Name:                      NumberClass,
			TreeMap_EntryClass.Name:               TreeMap_EntryClass,
			HashMap_NodeClass.Name:                HashMap_NodeClass,
			HashMapClass.Name:                     HashMapClass,
			TreeMapClass.Name:                     TreeMapClass,
			HashTable_EntryClass.Name:             HashTable_EntryClass,
			HashTableClass.Name:                   HashTableClass,
			TemplatesImplClass.Name:               TemplatesImplClass,
			RuntimeClass.Name:                     RuntimeClass,
			IntegerClass.Name:                     IntegerClass,
			AnnotationInvocationHandlerClass.Name: AnnotationInvocationHandlerClass,
		},
		parent: nil,
		interfaceMap: map[string]Interface{
			Serializable.Name: Serializable,
			Map.Name:          Map,
			Entry.Name:        Entry,
			Comparator.Name:   Comparator,
			Templates.Name:    Templates,
		},
	}
}

var contextClassLoader *ClassLoader = bootLoader

func GetContextClassLoader() *ClassLoader {
	return contextClassLoader
}

func SetContextClassLoader(loader *ClassLoader) {
	contextClassLoader = loader
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

func ClassForName(className string) (*Class, error) {
	class := bootLoader.LoadClass(className)
	if class != nil {
		return class, nil
	}
	return nil, fmt.Errorf("class %s not found", className)
}

var (
	Comparable   = Interface{Name: "java.lang.Comparable"}
	Serializable = Interface{Name: "java.lang.Serializable"}
	Map          = Interface{Name: "java.util.Map"}
	Entry        = Interface{Name: "java.util.Map$Entry"}
	Comparator   = Interface{Name: "java.util.Comparator"}
	Templates    = Interface{Name: "javax.xml.transform.Templates"}
)

var (
	BooleanClass = Class{
		Name:             "java.lang.Boolean",
		SerialVersionUID: JavaLongStrToUint64("-3665804199014368530L"),
		Implements:       []Interface{Serializable, Comparable},
		Fields:           []Field{},
	}
	ByteClass = Class{
		Name:       "java.lang.Byte",
		Super:      NumberClass.Name,
		Implements: []Interface{Comparable},
		Fields:     []Field{},
	}
	CharacterClass = Class{
		Name:             "java.lang.Character",
		SerialVersionUID: JavaLongStrToUint64("3786198910865385080L"),
		Implements:       []Interface{Serializable, Comparable},
		Fields:           []Field{},
	}
	DoubleClass = Class{
		Name:       "java.lang.Double",
		Super:      NumberClass.Name,
		Implements: []Interface{Comparable},
		Fields:     []Field{},
	}
)

var (
	StringClass = Class{
		Name:             "java.lang.String",
		SerialVersionUID: JavaLongStrToUint64("-6849794470754667710L"),
		AccessFlags:      AccPublic,
		Implements: []Interface{
			Serializable, {Name: "java.lang.Comparable"}, {Name: "java.lang.CharSequence"},
		},
		Fields: []Field{},
	}

	ObjectClass = Class{
		Name:        "java.lang.Object",
		AccessFlags: AccPublic,
		Implements:  make([]Interface, 0),
		Fields:      make([]Field, 0),
	}
	ClassArrayClass = Class{
		Name:             "[Ljava.lang.Class;",
		SerialVersionUID: JavaLongStrToUint64("-6118465897992725863L"),
		Implements:       make([]Interface, 0),
		Fields:           make([]Field, 0),
	}
	NumberClass = Class{
		Name:             "java.lang.Number",
		SerialVersionUID: JavaLongStrToUint64("-8742448824652078965L"),
		AccessFlags:      AccPublic,
		Implements:       []Interface{Serializable},
		Fields:           []Field{},
	}

	ClassLoaderClass = Class{
		Name:        "java.lang.ClassLoader",
		AccessFlags: AccPublic | AccAbstract,
		Implements:  make([]Interface, 0),
		Fields: []Field{
			{
				AccessFlags: AccPrivate | AccFinal,
				Descriptor:  "java.lang.ClassLoader",
				Name:        "parent",
			},
		},
	}
	ClassClass = Class{
		Name:        "java.lang.Class",
		AccessFlags: AccPublic,
		Implements:  []Interface{Serializable, {Name: "java.lang.GenericDeclaration"}, {Name: "java.lang.Type"}, {Name: "java.lang.AnnotatedElement"}},
		Fields:      []Field{},
	}
	ObjectArrayClass = Class{
		Name:             "[Ljava.lang.Object;",
		SerialVersionUID: JavaLongStrToUint64("-8012369246846506644L"),
		Fields:           make([]Field, 0),
		Implements:       []Interface{},
	}
	AbstractMapClass = Class{
		Name:        "java.util.AbstractMap",
		AccessFlags: AccPublic | AccAbstract,
		Implements:  []Interface{Map},
	}
	HashMap_NodeClass = Class{
		Name:        "java.util.HashMap$Node",
		AccessFlags: 0,
		Implements:  []Interface{Entry},
		Fields: []Field{
			{
				Name:        "hash",
				Descriptor:  "int",
				AccessFlags: AccFinal,
			},
			{
				Name:        "key",
				Descriptor:  "java.lang.Object",
				AccessFlags: AccFinal,
			},
			{
				Name:       "value",
				Descriptor: "java.lang.Object",
			},
			{
				Name:         "next",
				Descriptor:   "java.util.HashMap$Node",
				DefaultValue: &NULL,
			},
		},
	}
	HashMapClass = Class{
		Name: "java.util.HashMap",
		//Super:            "java.util.AbstractMap",
		SerialVersionUID: JavaLongStrToUint64("362498820763181265L"),
		Implements:       []Interface{Serializable, Map},
		Fields: []Field{
			{
				AccessFlags: AccTransient,
				Descriptor:  "int",
				Name:        "size",
			},
			{
				AccessFlags: AccFinal,
				Descriptor:  "float",
				Name:        "loadFactor",
			},
			{
				Descriptor: "int",
				Name:       "threshold",
			},

			{
				AccessFlags: AccTransient,
				Descriptor:  "java.util.HashMap$Node[]",
				Name:        "tab",
			},
		},
	}

	TreeMapClass = Class{
		Name:       "java.util.TreeMap",
		Super:      "java.util.AbstractMap",
		Implements: []Interface{{Name: "java.lang.Cloneable"}, Serializable},
		Fields: []Field{
			{
				Name:        "comparator",
				Descriptor:  "java.util.Comparator",
				AccessFlags: AccPrivate | AccFinal,
			},
			{
				Name:        "root",
				Descriptor:  "java.util.TreeMap$Entry",
				AccessFlags: AccPrivate | AccTransient,
			},
			{
				Name:        "size",
				Descriptor:  "int",
				AccessFlags: AccTransient | AccPrivate,
			},
			{
				Name:        "modCount",
				Descriptor:  "int",
				AccessFlags: AccTransient | AccPrivate,
			},
		},
	}

	TreeMap_EntryClass = Class{
		Name:        "java.util.TreeMap$Entry",
		AccessFlags: AccStatic | AccFinal,
		Implements:  []Interface{Entry, Serializable},
		Fields: []Field{
			{
				Name:       "key",
				Descriptor: "java.lang.Object",
			},
			{
				Name:       "value",
				Descriptor: "java.lang.Object",
			},
			{
				Name:       "left",
				Descriptor: "java.util.TreeMap$Entry",
			},
			{
				Name:       "right",
				Descriptor: "java.util.TreeMap$Entry",
			},
			{
				Name:       "parent",
				Descriptor: "java.util.TreeMap$Entry",
			},
		},
	}
	HashTable_EntryClass = Class{
		Name:        "java.util.HashTable$Entry",
		AccessFlags: AccStatic | AccPrivate,
		Implements:  []Interface{Entry},
		Fields: []Field{
			{
				Name:        "hash",
				Descriptor:  "int",
				AccessFlags: AccFinal,
			},
			{
				Name:        "key",
				Descriptor:  "java.lang.Object",
				AccessFlags: AccFinal,
			},
			{
				Name:       "value",
				Descriptor: "java.lang.Object",
			},
			{
				Name:         "next",
				Descriptor:   "java.util.HashTable$Entry",
				DefaultValue: &NULL,
			},
		},
	}

	HashTableClass = Class{
		Name:        "java.util.HashTable",
		AccessFlags: AccPublic,
		Implements:  []Interface{Serializable, Map},
		Fields: []Field{
			{
				Name:        "table",
				Descriptor:  "java.util.HashTable$Entry",
				AccessFlags: AccTransient | AccPrivate,
			},
		},
	}

	TemplatesImplClass = Class{
		Name:             "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
		AccessFlags:      AccPublic | AccFinal,
		SerialVersionUID: 673094361519270707,
		Implements:       []Interface{Serializable, Templates},
		Fields: []Field{
			{
				Name:        "_name",
				Descriptor:  "java.lang.String",
				AccessFlags: AccPrivate,
			},
			{
				Name:        "_bytecodes",
				Descriptor:  "byte[][]",
				AccessFlags: AccPrivate,
			},
		},
	}
	ProxyClass = Class{
		Name:             "java.lang.reflect.Proxy",
		SerialVersionUID: JavaLongStrToUint64("-2222568056686623797L"),
		Implements:       []Interface{Serializable},
		Fields:           []Field{},
	}
	AnnotationInvocationHandlerClass = Class{
		Name:             "sun.reflect.annotation.AnnotationInvocationHandler",
		SerialVersionUID: JavaLongStrToUint64("6182022883658399397L"),
		Implements:       []Interface{Serializable},
		Fields: []Field{
			{
				Name:        "memberValues",
				Descriptor:  Map.Name,
				AccessFlags: AccPrivate | AccFinal,
			},
			{
				Name:        "type",
				Descriptor:  ClassClass.Name,
				AccessFlags: AccPrivate | AccFinal,
			},
		},
	}
	PriorityQueueClass = Class{
		Name:             "java.util.PriorityQueue",
		SerialVersionUID: JavaLongStrToUint64("-7720805057305804111L"),
		Implements:       []Interface{Serializable},
		Fields: []Field{
			{
				Name:        "size",
				Descriptor:  "int",
				AccessFlags: AccPrivate,
			},
			{
				Name:        "comparator",
				Descriptor:  Comparator.Name,
				AccessFlags: AccPrivate | AccFinal,
			},
			{
				Name:        "modCount",
				Descriptor:  "int",
				AccessFlags: AccTransient,
			},

			{
				Name:        "queue",
				Descriptor:  "java.lang.Object[]",
				AccessFlags: AccTransient,
			},
		},
	}

	RuntimeClass = Class{
		Name:       "java.lang.Runtime",
		Implements: make([]Interface, 0),
		Fields:     make([]Field, 0),
	}
	IntegerClass = Class{
		Name:       "java.lang.Integer",
		Implements: make([]Interface, 0),
		Fields:     make([]Field, 0),
	}
)
