package serlib

import (
	"goserja/java"
)

var parseLongStr = java.JavaLongStrToUint64

const (
	StringDesc = "java.lang.String"
	ObjectDesc = "java.lang.Object"
	MapDesc    = "java.util.Map"
)

type (
	Class     = java.Class
	Interface = java.Interface
	Field     = java.Field
)

/*
存放java序列化要使用的各种java类的元数据
*/

var (
	Transformer  = Interface{Name: "org.apache.commons.collections.Transformer"}
	Serializable = java.Serializable
	KeyValue     = Interface{Name: "org.apache.commons.collections.KeyValue"}
)

var (
	CommonsCollection3Jar = java.Jar{
		Name:         "commons-collection.jar",
		LocationDesc: "",
		Note:         "cc依赖",
		Interfaces:   []Interface{Transformer, KeyValue},
		Classes: []Class{
			//ConstantTransformer.class
			{
				Name:             "org.apache.commons.collections.functors.ConstantTransformer",
				SerialVersionUID: parseLongStr("6374440726369055124L"),
				Implements:       []Interface{Serializable, Transformer},
				Fields: []Field{
					{
						Name:        "iConstant",
						Descriptor:  ObjectDesc,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
				},
			},
			//InvokerTransformer.class
			{
				Name:             "org.apache.commons.collections.functors.InvokerTransformer",
				SerialVersionUID: parseLongStr("-8653385846894047688L"),
				Implements:       []Interface{Serializable, Transformer},
				Fields: []Field{
					{
						Name:        "iArgs",
						Descriptor:  "java.lang.Object[]",
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
					{
						Name:        "iMethodName",
						Descriptor:  StringDesc,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
					{
						Name:        "iParamjava",
						Descriptor:  "java.lang.Class[]",
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
				},
			},
			//ChainedTransformer.class
			{
				Name:             "org.apache.commons.collections.functors.ChainedTransformer",
				SerialVersionUID: parseLongStr("3514945074733160196L"),
				Implements:       []Interface{Serializable, Transformer},
				Fields: []Field{
					{
						Name:        "iTransformers",
						Descriptor:  Transformer.Name + "[]",
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
				},
			},
			//AbstractMapDecorator.class
			{
				Name:       "org.apache.commons.collections.map.AbstractMapDecorator",
				Implements: []Interface{java.Map},
				Fields: []Field{
					{
						Name:        "map",
						Descriptor:  MapDesc,
						AccessFlags: java.AccProtected | java.AccTransient,
					},
				},
			},
			//LazyMap.class
			{
				Name:             "org.apache.commons.collections.map.LazyMap",
				SerialVersionUID: parseLongStr("7990956402564206740L"),
				Super:            "org.apache.commons.collections.map.AbstractMapDecorator",
				Implements:       []Interface{Serializable, java.Map},
				Fields: []Field{
					{
						Name:        "factory",
						Descriptor:  Transformer.Name,
						AccessFlags: java.AccFinal | java.AccProtected,
					},
				},
			},
			//TiedMapEntry.class
			{
				Name:             "org.apache.commons.collections.keyvalue.TiedMapEntry",
				SerialVersionUID: parseLongStr("-8453869361373831205L"),
				Implements:       []Interface{Serializable, KeyValue},
				Fields: []Field{
					{
						Name:        "key",
						Descriptor:  ObjectDesc,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
					{
						Name:        "map",
						Descriptor:  MapDesc,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
				},
			},
			// TransformedMap.class
			{
				Name:             "org.apache.commons.collections.map.TransformedMap",
				SerialVersionUID: parseLongStr("7023152376788900464L"),
				Super:            "org.apache.commons.collections.map.AbstractMapDecorator",
				Implements:       []Interface{Serializable, Transformer},
				Fields: []Field{
					{
						Name:        "keyTransformer",
						Descriptor:  Transformer.Name,
						AccessFlags: java.AccFinal | java.AccProtected,
					},
					{
						Name:        "valueTransformer",
						Descriptor:  Transformer.Name,
						AccessFlags: java.AccFinal | java.AccProtected,
					},
				},
			},
			// TransformingComparator.class
			{
				Name:             "org.apache.commons.collections4.comparators.TransformingComparator",
				SerialVersionUID: parseLongStr("3456940356043606220L"),
				Implements:       []Interface{Serializable, java.Comparator},
				Fields: []Field{
					{
						Name:        "decorated",
						Descriptor:  java.Comparator.Name,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
					{
						Name:        "transformer",
						Descriptor:  Transformer.Name,
						AccessFlags: java.AccFinal | java.AccPrivate,
					},
				},
			},
		},
	}
)
