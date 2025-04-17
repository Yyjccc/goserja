package java

import (
	"math"
	"strconv"
	"strings"
)

var NULL = Object{
	clazz:      nil,
	Fields:     nil,
	Descriptor: Descriptor("null"),
}

const (
	AccPublic       = 0x0001 //      CcFM_____			public
	AccPrivate      = 0x0002 //      _cFM_____			private
	AccProtected    = 0x0004 //      _cFM_____			protected
	AccStatic       = 0x0008 //      _cFM_____			static
	AccFinal        = 0x0010 //      CcFMP____			final
	AccSuper        = 0x0020 //      C________			super
	AccSynchronized = 0x0020 //      ___M_____			synchronized
	AccOpen         = 0x0020 // 9,   _____D___			open
	AccTransitive   = 0x0020 // 9,   ______R__			transitive
	AccVolatile     = 0x0040 //      __F______			volatile
	AccBridge       = 0x0040 //      ___M_____			bridge
	AccStaticPhase  = 0x0040 // 9,   ______R__			staticPhase
	AccTransient    = 0x0080 //      __F______		transient
	AccVarargs      = 0x0080 // 5.0  ___M_____		varargs
	AccNative       = 0x0100 //      ___M_____		native
	AccInterface    = 0x0200 //      Cc_______		interface
	AccAbstract     = 0x0400 //      Cc_M_____		abstract
	AccStrict       = 0x0800 //      ___M_____		strict
	AccSynthetic    = 0x1000 //      CcFMPDRXO		synthetic
	AccAnnotation   = 0x2000 // 5.0, Cc_______		annotation
	AccEnum         = 0x4000 // 5.0, CcF______		enum
	AccModule       = 0x8000 // 9,   C________		module
	AccMandated     = 0x8000 // ?,   ____PDRXO		mandated
)

type AccessFlags uint16

func (flags AccessFlags) IsPublic() bool       { return flags&AccPublic != 0 }
func (flags AccessFlags) IsPrivate() bool      { return flags&AccPrivate != 0 }
func (flags AccessFlags) IsProtected() bool    { return flags&AccProtected != 0 }
func (flags AccessFlags) IsStatic() bool       { return flags&AccStatic != 0 }
func (flags AccessFlags) IsFinal() bool        { return flags&AccFinal != 0 }
func (flags AccessFlags) IsSuper() bool        { return flags&AccSuper != 0 }
func (flags AccessFlags) IsSynchronized() bool { return flags&AccSynchronized != 0 }
func (flags AccessFlags) IsOpen() bool         { return flags&AccOpen != 0 }
func (flags AccessFlags) IsTransitive() bool   { return flags&AccTransitive != 0 }
func (flags AccessFlags) IsVolatile() bool     { return flags&AccVolatile != 0 }
func (flags AccessFlags) IsBridge() bool       { return flags&AccBridge != 0 }
func (flags AccessFlags) IsStaticPhase() bool  { return flags&AccStaticPhase != 0 }
func (flags AccessFlags) IsTransient() bool    { return flags&AccTransient != 0 }
func (flags AccessFlags) IsVarargs() bool      { return flags&AccVarargs != 0 }
func (flags AccessFlags) IsNative() bool       { return flags&AccNative != 0 }
func (flags AccessFlags) IsInterface() bool    { return flags&AccInterface != 0 }
func (flags AccessFlags) IsAbstract() bool     { return flags&AccAbstract != 0 }
func (flags AccessFlags) IsStrict() bool       { return flags&AccStrict != 0 }
func (flags AccessFlags) IsSynthetic() bool    { return flags&AccSynthetic != 0 }
func (flags AccessFlags) IsAnnotation() bool   { return flags&AccAnnotation != 0 }
func (flags AccessFlags) IsEnum() bool         { return flags&AccEnum != 0 }
func (flags AccessFlags) IsModule() bool       { return flags&AccModule != 0 }
func (flags AccessFlags) IsMandated() bool     { return flags&AccMandated != 0 }

// Descriptor 类型描述符,直接存储java类型全称
type Descriptor string

func (d Descriptor) IsPrimitive() bool {
	_, ok := reverseTypeMap[string(d)]
	return ok
}

func (d Descriptor) IsArray() bool {
	return strings.Contains(string(d), "[]")
}

func (d Descriptor) Value() string {
	val := string(d)
	// 如果是基本类型，直接返回描述符
	switch val {
	case "null":
		return "null"
	case "byte":
		return "B"
	case "char":
		return "C"
	case "double":
		return "D"
	case "float":
		return "F"
	case "int":
		return "I"
	case "long":
		return "J"
	case "short":
		return "S"
	case "boolean":
		return "Z"
	case "void":
		return "V"
	}

	// 如果是数组类型，例如 [][]java.lang.String [][]byte
	if strings.HasPrefix(val, "[") {
		fullName := strings.ReplaceAll(val, "[]", "")
		count := strings.Count(val, "[]")
		return strings.Repeat("[", count) + Descriptor(fullName).Value()
	}
	// 否则是普通类名，添加前缀 "L" 和后缀 ";"
	return "L" + strings.ReplaceAll(val, ".", "/") + ";"
}

// _toDescriptor 将类路径转为类型描述符
func _toDescriptor(classPath string) string {
	// 如果是基本类型，直接返回描述符
	switch classPath {
	case "byte":
		return "B"
	case "char":
		return "C"
	case "double":
		return "D"
	case "float":
		return "F"
	case "int":
		return "I"
	case "long":
		return "J"
	case "short":
		return "S"
	case "boolean":
		return "Z"
	case "void":
		return "V"
	}

	// 如果是数组类型，例如 [Ljava/lang/String;
	if strings.HasPrefix(classPath, "[") {
		return classPath
	}

	// 否则是普通类名，添加前缀 "L" 和后缀 ";"
	return "L" + classPath + ";"
}

// 类型映射表，用于将 JVM 类型标记转换为 Java 类型
var typeMap = map[string]string{
	"V": "void",
	"I": "int",
	"B": "byte",
	"C": "char",
	"D": "double",
	"F": "float",
	"J": "long",
	"S": "short",
	"Z": "boolean",
}

var reverseTypeMap = map[string]string{
	"void":    "V",
	"int":     "I",
	"byte":    "B",
	"char":    "C",
	"double":  "D",
	"float":   "F",
	"long":    "J",
	"short":   "S",
	"boolean": "Z",
}

func getBaseType(raw string) string {
	return _toDescriptor(raw)
}

func initBaseTypeValue(descriptor string) interface{} {
	switch descriptor {
	case "void":
		panic("unexpected void type")
	case "int":
		return 0
	case "byte":
		return byte(0)
	case "char":
		return rune(0)
	case "double":
		return float64(0)
	case "float":
		return float32(0)
	case "long":
		return int64(0)
	case "short":
		return int16(0)
	case "bool":
		return false
	default:
		panic("unexpected descriptor: " + descriptor)
	}
}

// ToClassDescriptor 将 Java 全类名转换为类描述符（支持数组）
func ToClassDescriptor(fullClassName string) string {
	if s, ok := reverseTypeMap[fullClassName]; ok {
		return s
	}
	arrayDim := 0
	// 统计数组维度，并去掉 "[]" 部分
	for strings.HasSuffix(fullClassName, "[]") {
		arrayDim++
		fullClassName = strings.TrimSuffix(fullClassName, "[]")
	}

	var descriptor string
	if primitive, exists := reverseTypeMap[fullClassName]; exists {
		// 基本数据类型直接映射
		descriptor = primitive
	} else {
		// 对象类型，加前缀 "L" 和后缀 ";"
		descriptor = "L" + strings.ReplaceAll(fullClassName, ".", "/") + ";"
	}

	// 根据数组维度加前缀 "["
	return strings.Repeat("[", arrayDim) + descriptor
}

var arrClazzUIDMap = map[string]uint64{
	"[[B":                 10206066974587786966,
	"[B":                  12462330947884831968,
	"[Ljava.lang.Class;":  JavaLongStrToUint64("-6118465897992725863L"),
	"[Ljava.lang.Object;": 10434374826863044972,
	"[Lorg.apache.commons.collections.Transformer;": JavaLongStrToUint64("-4803604734341277543L"),
}

func AddArrClassSerUID(desc string, serUID uint64) {
	arrClazzUIDMap[desc] = serUID
}

func JavaLongStrToUint64(s string) uint64 {
	// 去除字符串末尾的 'L' 或 'l'
	s = strings.TrimSuffix(s, "L")
	s = strings.TrimSuffix(s, "l")

	// 解析字符串为 int64
	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	// 如果值为负数，转换为对应的 uint64 值
	if value < 0 {
		return uint64(value) + math.MaxUint64 + 1
	}
	return uint64(value)

}

// 获取序列化uid 数组类
func GetSerUIDbyName(desc string) uint64 {
	if v, ok := arrClazzUIDMap[desc]; ok {
		return v
	}
	return 0
}
