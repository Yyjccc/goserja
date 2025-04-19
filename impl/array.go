package impl

import (
	"goserja/java"
	"reflect"
	"strings"
)

var PrimitiveArrayTypeMap = map[string]reflect.Type{
	"bool":   reflect.TypeOf(false),
	"byte":   reflect.TypeOf(byte(0)),
	"short":  reflect.TypeOf(int16(0)),
	"char":   reflect.TypeOf(int16(0)),
	"int":    reflect.TypeOf(int32(0)),
	"long":   reflect.TypeOf(int64(0)),
	"float":  reflect.TypeOf(float32(0)),
	"double": reflect.TypeOf(float64(0)),
}

// 判断是否为数组类型
func IsArrayOrSlice(val interface{}) bool {
	t := reflect.TypeOf(val)
	return t.Kind() == reflect.Array || t.Kind() == reflect.Slice
}

// 序列化 数组类型
func (js *JavaSerializer) writeArray(desc java.Descriptor, val interface{}) {

	length, _ := getSliceLength(val)
	if length == 0 {
		js.writer.WriteByte(TC_NULL)
		return
	}
	className := string(desc)
	clazz := &java.Class{
		Name:             className,
		SerialVersionUID: java.GetSerUIDbyName(className),
		Implements:       make([]java.Interface, 0),
		Fields:           make([]java.Field, 0),
	}

	js.writer.WriteByte(TC_ARRAY)
	js.writeClassDesc(clazz)

	js.handles.Assign(val)

	// 检查 data 是否为切片或数组
	switch desc.Value() {
	case "":
		return
	case "[B":
		data := val.([]byte)
		js.writer.WriteInt(int32((len(data))))
		js.writer.WriteBytes(data)
		return

	case "[Ljava.lang.Class;":
		js.writeClassArray(val.([]java.Class))
		return
	}
	//pass
	v := reflect.ValueOf(val)
	//普通对象数组或者嵌套数组

	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		js.writer.WriteUint32(uint32(v.Len()))
		for i := 0; i < v.Len(); i++ {
			element := v.Index(i).Interface()
			eleType := reflect.TypeOf(element)
			element = ConvertToPointer(element)
			if obj, ok := element.(*java.Object); ok {
				o := obj.UnWrap()
				js.WriteAllTypeData(o, &desc)
				continue
			}
			if class, ok := element.(*java.Class); ok {
				js.writeClassObject(class)
				continue
			}
			if eleType.Kind() == reflect.Slice || eleType.Kind() == reflect.Array {
				// 递归处理嵌套数组
				if strings.HasPrefix(desc.Value(), "[") {
					desc = java.Descriptor(strings.Replace(string(desc), "[]", "", 1))
				}
				js.writeArray(desc, element)

			} else {
				panic("Unsupported array element type: " + eleType.String())
			}
		}
	}

}

func UwrapObj(val interface{}) interface{} {
	if obj, ok := val.(java.Object); ok {
		return obj.UnWrap()
	}
	return val
}

func GetDesc(val interface{}) java.Descriptor {
	depth := getSliceDepth(val)
	element := getInnerElement(val)
	element = UwrapObj(element)
	if element == nil {
		return ""
	}
	arrDims := strings.Repeat("[]", depth)
	switch element.(type) {
	case java.Class:
		return java.Descriptor("java.lang.Class" + arrDims)
	case java.Object:
		object := element.(java.Object)
		if object.Descriptor != "" {
			return java.Descriptor("java.lang.Object" + arrDims)
		}
		return java.Descriptor(object.GetClass().Name + arrDims)
	case byte:
		return java.Descriptor("byte" + arrDims)
	case int:
		return java.Descriptor("int" + arrDims)
	case int32:
		return java.Descriptor("int" + arrDims)
	case int16:
		return java.Descriptor("short" + arrDims)
	case int64:
		return java.Descriptor("long" + arrDims)
	case float32:
		return java.Descriptor("float" + arrDims)
	case float64:
		return java.Descriptor("double" + arrDims)
	case bool:
		return java.Descriptor("bool" + arrDims)
	case string:
		return java.Descriptor("java.lang.String" + arrDims)
	}
	return ""
}

// 计算多层切片的嵌套层数
func getSliceDepth(val interface{}) int {
	t := reflect.TypeOf(val)
	depth := 0

	for t.Kind() == reflect.Slice {
		depth++
		t = t.Elem() // 进入下一层
	}
	return depth
}

// 获取最里层的一个元素
func getInnerElement(val interface{}) interface{} {
	v := reflect.ValueOf(val)

	// 递归进入最深层的 slice
	for v.Kind() == reflect.Slice && v.Len() > 0 {
		v = v.Index(0) // 取第一个元素
	}

	// 如果最终是基本类型或非空值，则返回
	if v.IsValid() {
		return v.Interface()
	}
	return nil
}

// ConvertToPointer 将结构体转换为结构体指针
func ConvertToPointer(val interface{}) interface{} {
	v := reflect.ValueOf(val)

	// 如果已经是指针，直接返回
	if v.Kind() == reflect.Ptr {
		return val
	}

	// 如果是结构体，则创建指针并返回
	if v.Kind() == reflect.Struct {
		ptr := reflect.New(v.Type()) // 创建指针
		ptr.Elem().Set(v)            // 复制原始值
		return ptr.Interface()
	}

	// 不是结构体，返回原值
	return val
}

func getSliceLength(val interface{}) (int, bool) {
	// 获取 val 的反射值
	v := reflect.ValueOf(val)

	// 检查 val 的类型是否为切片
	if v.Kind() == reflect.Slice {
		// 返回切片的长度
		return v.Len(), true
	}

	// 如果不是切片，返回 0 和 false
	return 0, false
}
