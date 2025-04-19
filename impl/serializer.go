package impl

import (
	"fmt"
	"goserja/java"
	"math"
	"strings"
)

// 序列化相关的常量
const (
	STREAM_MAGIC   = 0xACED
	STREAM_VERSION = 5
	baseWireHandle = 0x7e0000

	TC_NULL          = byte(0x70)
	TC_REFERENCE     = byte(0x71)
	TC_CLASSDESC     = byte(0x72)
	TC_OBJECT        = byte(0x73)
	TC_STRING        = byte(0x74) //短字符串(长度<65535)
	TC_ARRAY         = byte(0x75)
	TC_CLASS         = byte(0x76)
	TC_BLOCKDATA     = byte(0x77) // Block 数据标志
	TC_ENDBLOCKDATA  = byte(0x78)
	TC_RESET         = byte(0x79)
	TC_BLOCKDATALONG = byte(0x7a) // 长块数据标记
	// TC_EXCEPTION      = 0x7b
	TC_LONGSTRING     = byte(0x7c) //长字符串
	TC_PROXYCLASSDESC = byte(0x7d)
	TC_ENUM           = byte(0x7E)

	SC_WRITE_METHOD   = 0x01
	SC_SERIALIZABLE   = 0x02
	SC_EXTERNALIZABLE = 0x04
	SC_BLOCK_DATA     = 0x08
	SC_ENUM           = 0x10
)

func ComputerFlag(c *java.Class) byte {
	flag := byte(0x00)
	if c.WriteObjectData != nil {
		flag |= SC_WRITE_METHOD
	}
	for _, i := range c.Implements {
		if i == java.Serializable {
			flag |= SC_SERIALIZABLE
			break
		}
	}
	if c.IsEnum() {
		flag |= SC_ENUM
	}
	return flag
}

// JavaSerializer 负责序列化逻辑
type JavaSerializer struct {
	writer  *BlockDataWriter
	handles *HandleTable
	curDesc *java.Class
}

func (j *JavaSerializer) GetWriter() *BlockDataWriter {
	return j.writer
}

func NewJavaSerializer() *JavaSerializer {
	js := &JavaSerializer{
		writer:  NewBlockDataWriter(false),
		handles: NewHandleTable(10, 3.00),
	}
	js.init()
	return js
}

func (js *JavaSerializer) init() {
	js.writer.WriteUint16(STREAM_MAGIC)
	js.writer.WriteUint16(STREAM_VERSION)
}

// SetBlkMode Ref: ObjectOutputStream#setBlockDataMode
func (js *JavaSerializer) SetBlkMode(b bool) {
	if js.writer.blockMode == b {
		return
	}
	js.writer.Flush()
	js.writer.blockMode = b
}

func (js JavaSerializer) GetByteData() []byte {
	return js.writer.Bytes()
}

func (js *JavaSerializer) Reset() {
	js.SetBlkMode(false)
	js.writer.WriteByte(TC_RESET)
	js.handles.Clear()
	js.SetBlkMode(true)
}

func (js *JavaSerializer) WriteEnum(enum *java.Enum) {
	js.writer.WriteByte(TC_ENUM)
	js.writeClassDesc(&enum.Class)
	//writeClassDesc((sdesc.forClass() == Enum.class) ? desc : sdesc, false);
	js.handles.Assign(enum)
	js.WriteString(enum.Name)
}

func (js *JavaSerializer) writeObject(obj *java.Object) {
	js.SetBlkMode(false)
	if obj == nil {
		js.writer.WriteByte(TC_NULL)
		return
	}
	if obj.GetClass() == nil {
		js.writer.WriteByte(TC_NULL)
		return
	}

	// 处理对象引用
	index := js.handles.Lookup(*obj)
	if index >= 0 {
		js.writeHandle(index)
		return
	}

	//1.写入标志
	js.writer.WriteByte(TC_OBJECT)

	//2.写入类描述信息
	js.writeClassDesc(obj.GetClass())

	js.handles.Assign(*obj)

	//3.写入字段数据
	js.writeFieldData(obj)
	js.SetBlkMode(false)
	//js.writer.WriteByte(TC_ENDBLOCKDATA)

}

func (js *JavaSerializer) DefualtWriteData(obj *java.Object) {
	for _, field := range js.curDesc.Fields {
		if field.AccessFlags.IsTransient() {
			// 非序列化字段跳过
			continue
		}
		value := obj.Fields[field.Name]
		value = UwrapObj(value)
		js.writeFieldValue(java.Descriptor(field.Descriptor), value)
	}
}

// 字段数据写入
func (js *JavaSerializer) writeFieldData(obj *java.Object) {
	//获取所有父类
	classList := []*java.Class{obj.GetClass()}
	curClazz := obj.GetClass()
	for {
		superClazz := curClazz.SuperClass()
		if superClazz == nil {
			break
		}
		classList = append(classList, superClazz)
		curClazz = superClazz
	}

	for _, class := range classList {
		js.curDesc = class
		if class.WriteObjectData != nil {
			// 如果存在writeObject方法则调用
			js.SetBlkMode(true)
			class.WriteObjectData(js, obj)
			js.SetBlkMode(false)
			js.writer.WriteByte(TC_ENDBLOCKDATA)

		} else {
			// DefaultWriteData 默认方式写入字段数据
			js.SetBlkMode(false)
			js.DefualtWriteData(obj)
		}
	}

}

func (js *JavaSerializer) writeHandle(offset int) {
	js.writer.WriteByte(TC_REFERENCE)
	js.writer.WriteInt(int32(baseWireHandle + offset))
}

func (js *JavaSerializer) writeClassDesc(clazz *java.Class) {
	if clazz == nil {
		js.writer.WriteByte(TC_NULL)
		return
	}
	if handle := js.handles.Lookup(clazz); handle != -1 {
		js.writeHandle(handle)
		return
	}
	if clazz.IsProxy {
		js.writeProxyDesc(clazz)
	} else {
		js.writeNonProxyDesc(clazz)
	}

}

// 类描述写入 writeNonProxyDesc
func (js *JavaSerializer) writeNonProxyDesc(class *java.Class) {
	//检查是否存在handle
	index := js.handles.Lookup(*class)
	if index >= 0 {
		js.writeHandle(index)
		return
	}
	js.handles.Assign(*class)

	js.writer.WriteByte(TC_CLASSDESC)

	//1.写入类名
	// 数组类名混合写法
	name := class.Name
	if strings.Contains(name, "[]") {
		name = strings.ReplaceAll(java.Descriptor(name).Value(), "/", ".")
	}
	js.writer.WriteString(name)
	//2.写入uid
	js.writer.WriteUint64(class.GetSerialVersionUID()) // serialVersionUID
	//3.写入flag
	//计算flag
	js.writer.WriteByte(ComputerFlag(class)) // SC_SERIALIZABLE

	var validFields []java.Field
	for _, f := range class.Fields {
		if !f.AccessFlags.IsTransient() {
			validFields = append(validFields, f)
		}
	}
	//4.写入field 数量
	js.writer.WriteUint16(uint16(len(validFields)))
	//5.循环写入field 信息
	for _, f := range validFields {
		js.writeFieldDescriptor(f)
	}
	//6.写入block结束符
	js.writer.WriteByte(TC_ENDBLOCKDATA)
	//7.写入父类描述信息
	//if class.Super != "" {
	//	superClazz, err := java.ClassForName(class.Super)
	//	if err != nil {
	//		return
	//	}
	//	js.writeClassDesc(superClazz)
	//} else {
	js.writer.WriteByte(TC_NULL) // 父类描述
	//}

}

func (js *JavaSerializer) writeProxyDesc(proxy *java.Class) {
	js.writer.WriteByte(TC_PROXYCLASSDESC)
	js.handles.Assign(*proxy)
	js.WriteInt(len(proxy.ProxyInterface))
	for _, i := range proxy.ProxyInterface {
		js.writer.WriteString(i.Name)
	}
	js.writer.WriteByte(TC_ENDBLOCKDATA)
	js.writeClassDesc(proxy.SuperClass())
}

// 字段描述写入
func (js *JavaSerializer) writeFieldDescriptor(field java.Field) {
	descriptor := field.GetDescriptor()
	typeCode := descriptor[0]
	//1.写入类型描述符
	js.writer.WriteByte(typeCode)
	//2.写入字段名称
	js.writer.WriteString(field.Name)
	//3.如果是私有变量写入 全量的类型描述符
	if rune(typeCode) == 'L' || rune(typeCode) == '[' {
		js.WriteString(descriptor)
	}
}

func (js *JavaSerializer) WriteAllTypeData(val interface{}, desc *java.Descriptor) {
	if val == nil {
		js.writer.WriteByte(TC_NULL)
		return
	}
	val = UwrapObj(val)
	val = ConvertToPointer(val)
	//类型断言
	switch val.(type) {
	case string:
		js.WriteString(val.(string))
		return
	case int:
		js.writer.WriteUint32(uint32(val.(int)))
		return
	case int64:
		js.writer.WriteUint64(uint64(val.(int64)))
		return
	case byte:
		js.writer.WriteByte(val.(byte))
		return
	case []byte:
		js.writer.WriteBytes(val.([]byte))
		return
	case float32:
		js.writer.WriteUint32(math.Float32bits(val.(float32)))
		return
	case float64:
		js.writer.WriteUint64(math.Float64bits((val.(float64))))
		return
	case *java.Object:
		js.writeObject(val.(*java.Object))
		return
	case *java.Class:
		js.writeClassObject(val.(*java.Class))
		return

	default:
		if IsArrayOrSlice(val) {

			var descriptor java.Descriptor
			if desc == nil {
				descriptor = GetDesc(val)
			} else {
				descriptor = *desc
			}
			js.writeArray(descriptor, val)
			return
		}
		panic(fmt.Sprintf("unsupported serialize go type:%v", val))
	}
}

// 字段值写入
func (js *JavaSerializer) writeFieldValue(descriptor java.Descriptor, value interface{}) {
	value = ConvertToPointer(value)
	js.WriteAllTypeData(value, &descriptor)
}

// 字符串处理
func (js *JavaSerializer) WriteString(s string) {
	index := js.handles.Lookup(s)
	if index >= 0 {
		js.writeHandle(index)
		return
	}

	js.handles.Assign(s)

	strLen := len(s)
	if strLen <= 65535 {
		js.writer.WriteByte(TC_STRING)
		js.writer.WriteString(s)
	} else {
		//可能会出错，一般不会出现这个分支
		js.writer.WriteByte(TC_LONGSTRING)
		js.writer.WriteUint64(uint64(strLen))
		js.writer.WriteString(s)
	}

}

func (js *JavaSerializer) writeClassArray(objs []java.Class) {
	// 序列化每个 Class 对象
	for _, obj := range objs {
		js.writeClassObject(&obj)
	}
}

func (js *JavaSerializer) writeClassObject(class *java.Class) {
	loadedClass := LoadedClass{Class: *class}
	//对加载的Class同步缓存
	index := js.handles.Lookup(loadedClass)
	if index >= 0 {
		js.writeHandle(index)
		return
	}
	js.writer.WriteByte(TC_CLASS) // 标记对象
	js.writeClassDesc(class)      // 写入类描述信息
	js.handles.Assign(loadedClass)
}

func (js *JavaSerializer) WriteObject(val interface{}) error {
	//对包装；类型进行解耦
	val = ConvertToPointer(val)
	switch val.(type) {
	case *java.Object:
		js.writeObject(val.(*java.Object))
		break
	case string:
		js.WriteString(val.(string))
		break

	default:
		return fmt.Errorf("unsupported serialize go type:%v", val)
	}
	return nil
}

func (js *JavaSerializer) WriteBoolean(val bool) {
	byteVal := byte(0)
	if val {
		byteVal = byte(1)
	}
	js.writer.WriteByte(byteVal)
}

// 对应java 中 defaultWriteObject 方法 ,在writeObject方法中使用
func (js *JavaSerializer) DefaultWriteObject(obj *java.Object) {
	js.SetBlkMode(false)
	js.defaultWriteFields(obj)
	js.SetBlkMode(true)
}

// defaultWriteFields 对应java defaultWriteFields方法
func (js *JavaSerializer) defaultWriteFields(obj *java.Object) {
	//写入基本数据类型
	for _, field := range obj.GetClass().Fields {
		if !field.IsTransient() && field.IsPrimitive() {
			js.WriteAllTypeData(obj.Fields[field.Name], nil)
		}
	}
	//写入其他可序列化的类型
	for _, field := range obj.GetClass().Fields {
		if !field.IsTransient() && !field.IsPrimitive() {
			descriptor := java.Descriptor(field.Descriptor)
			js.WriteAllTypeData(obj.Fields[field.Name], &descriptor)
		}

	}
}

func (js *JavaSerializer) WriteInt(i int) {
	js.writer.WriteUint32(uint32(i))
}
