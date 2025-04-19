package impl

import (
	"errors"
	"fmt"
	"goserja/java"
	"log"
	"reflect"
	"strings"
)

var (
	IgnoreReadFull = false
)

type JavaDeserializer struct {
	Reader  *BlockDataReader
	handles *HandleTable
	CurDesc *java.Class
	CurObj  *java.Object
}

func (js *JavaDeserializer) GetReader() *BlockDataReader {
	return js.Reader
}

func NewJavaDeserializer(data []byte) *JavaDeserializer {
	return &JavaDeserializer{
		Reader:  NewBlockDataReader(data),
		handles: NewHandleTable(10, 3.00),
	}
}
func ReadObject(data []byte) (interface{}, error) {
	deserializer := NewJavaDeserializer(data)
	if err := deserializer.readMagic(); err != nil {
		return nil, err
	}
	object, err := deserializer.readObject0()
	if err == nil {
		if !IgnoreReadFull && deserializer.Reader.Remaining() > 0 {
			err = errors.New("unexpected end of EOF,unread in stream. maybe exist readObject method not register.")
		}
	}
	return object, err
}

func (d *JavaDeserializer) readMagic() error {
	fid, err := d.Reader.ReadShort()
	version, err := d.Reader.ReadShort()
	if err != nil {
		return err
	}
	if STREAM_MAGIC != uint16(fid) {
		return errors.New("invalid stream header : magic number mismatch.")
	}
	if STREAM_VERSION != int(version) {
		return errors.New("invalid stream header : version number mismatch.")
	}
	return nil
}

func (d *JavaDeserializer) readObject0() (interface{}, error) {
	oldMode := d.Reader.blockMode
	defer d.SetBlkMode(oldMode)
	if oldMode {
		d.SetBlkMode(false)
	}
	var tc byte
	var err error
	for {
		tc, err = d.Reader.Peek()
		if err != nil {
			return nil, err
		}

		if tc != TC_RESET {
			break
		}
		_, _ = d.Reader.ReadByte()
	}

	switch tc {
	case TC_NULL:
		return d.readNull()
	case TC_REFERENCE:
		return d.readHandle()
	case TC_CLASS:
		return d.readClass()
	case TC_CLASSDESC, TC_PROXYCLASSDESC:
		return d.readClassDesc()
	case TC_STRING, TC_LONGSTRING:
		return d.readString()
	case TC_ARRAY:
		return d.readArray()
	case TC_ENUM:
		return nil, err
	case TC_OBJECT:
		return d.readOrdinaryObject()
	case TC_BLOCKDATA, TC_BLOCKDATALONG:
		return nil, err
	case TC_ENDBLOCKDATA:
		return nil, err
	default:
		return nil, errors.New("invalid object type")
	}

}

func (d *JavaDeserializer) readNull() (*java.Object, error) {
	if b, err := d.Reader.ReadByte(); err != nil || b != TC_NULL {
		return nil, errors.New("InternalError")
	}
	return &java.NULL, nil
}

func (d *JavaDeserializer) readHandle() (interface{}, error) {
	d.Reader.ReadByte()
	handle, err := d.Reader.ReadInt()
	if err != nil {
		return nil, err
	}
	passHandle := handle - baseWireHandle
	if passHandle < 0 || int(passHandle) > d.handles.Size() {
		return nil, errors.New("invalid handle value")
	}
	return d.handles.LookupObject(passHandle), nil
}

func (d *JavaDeserializer) readString() (*java.Object, error) {
	var str string
	tc, err := d.Reader.ReadByte()
	if err != nil {
		return nil, err
	}
	switch tc {
	case TC_STRING:
		str, err = d.Reader.ReadUTF()
		break
	case TC_LONGSTRING:
		str, err = d.Reader.ReadLongUTF()
		break
	default:
		return nil, errors.New("invalid object type")
	}
	d.handles.Assign(str)
	obj := java.NewString(str)
	return &obj, err
}

func (d *JavaDeserializer) readClass() (*java.Class, error) {
	d.Reader.ReadByte()
	clazz, err := d.readClassDesc()
	loaded := &LoadedClass{Class: *clazz}
	if err != nil {
		return nil, err
	}
	d.handles.Assign(loaded)
	return clazz, nil

}

func (d *JavaDeserializer) readClassDesc() (*java.Class, error) {
	tc, err := d.Reader.Peek()
	if err != nil {
		return nil, err
	}
	switch tc {
	case TC_NULL:
		_, err = d.readNull()
		return nil, err
	case TC_REFERENCE:
		handle, err := d.readHandle()
		return handle.(*java.Class), err
	case TC_PROXYCLASSDESC:
		return d.readProxyDesc()
	case TC_CLASSDESC:
		return d.readNonProxyDesc()
	default:
		return nil, errors.New("invalid object type on reading class")
	}
}

func (d *JavaDeserializer) readProxyDesc() (*java.Class, error) {
	d.Reader.ReadByte()
	class := &java.Class{
		Name:       java.ProxyClass.Name + "$$",
		IsProxy:    true,
		Implements: make([]java.Interface, 0),
		Fields:     make([]java.Field, 0),
	}
	d.handles.Assign(class)
	numIfaces, err := d.Reader.ReadInt()
	if err != nil {
		return nil, err
	}
	var ifaces []java.Interface
	for i := 0; i < int(numIfaces); i++ {
		name, err := d.Reader.ReadUTF()
		if err != nil {
			return nil, err
		}
		ifaces = append(ifaces, java.Interface{Name: name})
	}
	class.ProxyInterface = ifaces
	d.Reader.ReadByte() //block
	superClazz, err := d.readClassDesc()
	if err != nil {
		return nil, err
	}
	super := ""
	if superClazz != nil {
		super = superClazz.Name
	}
	class.Super = super

	return class, nil
}

func (d *JavaDeserializer) readNonProxyDesc() (*java.Class, error) {
	d.Reader.ReadByte()

	name, err := d.Reader.ReadUTF()
	class := &java.Class{
		Name:       name,
		Implements: make([]java.Interface, 0),
	}
	d.handles.Assign(class)
	if err != nil {
		return nil, err
	}
	suid, err := d.Reader.ReadLong()
	if err != nil {
		return nil, err
	}
	class.SerialVersionUID = uint64(suid)
	_, err = d.Reader.ReadByte() //flag
	if err != nil {
		return nil, err
	}
	fieldNum, err := d.Reader.ReadShort()
	if err != nil {
		return nil, err
	}
	fieldList := make([]java.Field, 0)
	for i := 0; i < int(fieldNum); i++ {

		var desc java.Descriptor
		tcode, err := d.Reader.ReadByte()
		if err != nil {
			return nil, err
		}
		fname, err := d.Reader.ReadString()
		if err != nil {
			return nil, err
		}
		desc = java.MakeDescriptor(string(tcode))
		if tcode == 'L' || tcode == '[' {
			descName, err := d.readTypeString()
			if err != nil {
				return nil, err
			}
			desc = java.MakeDescriptor(descName)
		}

		fieldList = append(fieldList, java.Field{
			Descriptor: string(desc),
			Name:       fname,
		})
	}
	loadClass := java.LoadClass(name)
	class.Fields = fieldList
	d.Reader.ReadByte() // block
	superClazz, err := d.readClassDesc()
	if err != nil {
		return nil, err
	}
	super := ""
	if superClazz != nil {
		super = superClazz.Name
	}
	class.Super = super
	if loadClass != nil {
		err := class.MustEquals(loadClass)
		if err != nil {
			return loadClass, nil
		}
		class.ReadObjectData = loadClass.ReadObjectData
		class.WriteObjectData = loadClass.WriteObjectData
	} else {
		log.Printf("[Warn] cannot load class :" + class.Name)
	}

	return class, nil
}

func (d *JavaDeserializer) readTypeString() (string, error) {
	tc, err := d.Reader.Peek()
	if err != nil {
		return "", err
	}
	switch tc {
	case TC_NULL:
		d.readNull()
		return "", nil
	case TC_REFERENCE:
		handle, err := d.readHandle()
		if err != nil {
			return "", err
		}
		if strObj, ok := handle.(*java.Object); ok {
			return strObj.Fields["val"].(string), nil
		}
		return handle.(string), nil
	case TC_STRING, TC_LONGSTRING:
		str, err := d.readString()
		if err != nil {
			return "", err
		}

		return str.Fields["val"].(string), nil
	default:
		return "", errors.New("invalid object type")
	}
}

func (d *JavaDeserializer) readArray() (interface{}, error) {
	d.Reader.ReadByte()
	desc, err := d.readClassDesc()
	if err != nil {
		return nil, err
	}
	if desc == nil {
		panic("read array error")
	} else if desc.IsPrimitive() {
		return d.ReadPrimitiveArray(java.MakeDescriptor(desc.Name))
	} else {
		length, err := d.Reader.ReadInt()
		if err != nil {
			return nil, err
		}
		if desc.Name == "[Ljava.lang.Class;" {
			//Class
			clazzArr := make([]*java.Class, 0)
			ca := &clazzArr
			d.handles.Assign(ca)
			for i := 0; i < int(length); i++ {
				o, err := d.readObject0()
				if err != nil {
					return nil, err
				}
				*ca = append(*ca, o.(*java.Class))
			}
			return ca, nil
		} else {
			// Object
			objarr := make([]*java.Object, 0)
			oa := &objarr
			d.handles.Assign(oa)
			for i := 0; i < int(length); i++ {
				o, err := d.readObject0()
				if err != nil {
					return nil, err
				}
				*oa = append(*oa, o.(*java.Object))
			}
			return oa, nil
		}
	}
	return nil, nil
}

func (d *JavaDeserializer) readOrdinaryObject() (*java.Object, error) {
	d.Reader.ReadByte()
	desc, err := d.readClassDesc()
	if err != nil {
		return nil, err
	}
	if desc.Name == java.StringClass.Name || desc.Name == java.ClassClass.Name {
		return nil, errors.New("invalid class descriptor")
	}
	object := desc.NewInstance(java.GetContextClassLoader())
	obj := &object
	d.handles.Assign(obj)
	err = d.readSerialData(obj)
	if err != nil {
		return nil, err
	}

	return obj, err
}

func (d *JavaDeserializer) readSerialData(obj *java.Object) error {
	curClazz := obj.GetClass()
	classList := []*java.Class{obj.GetClass()}
	d.CurObj = obj
	for {
		superClazz := curClazz.SuperClass()
		if superClazz == nil {
			break
		}
		classList = append(classList, superClazz)
		curClazz = superClazz
	}
	for _, class := range classList {
		d.CurDesc = class
		if class.ReadObjectData != nil {
			d.SetBlkMode(true)
			if err := class.ReadObjectData(d, obj); err != nil {
				return err
			}
			d.SetBlkMode(false)
		} else {
			if err := d.defaultReadFields(obj); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *JavaDeserializer) defaultReadFields(obj *java.Object) error {
	class := d.CurDesc
	for _, field := range class.Fields {
		if field.AccessFlags.IsTransient() {
			// 非序列化字段跳过
			continue
		}
		desc := java.Descriptor(field.Descriptor)
		val, err := d.readAllTypeField(desc)
		if err != nil {
			return err
		}
		if object, ok := val.(*java.Object); ok {
			obj.Fields[field.Name] = object.UnWrap()
		} else {
			obj.Fields[field.Name] = val
		}

	}
	return nil
}

func (d *JavaDeserializer) readAllTypeField(desc java.Descriptor) (interface{}, error) {
	descStr := string(desc)
	switch descStr {
	case "bool":
		return d.Reader.ReadBool()
	case "byte":
		return d.Reader.ReadByte()
	case "char":
		return d.Reader.ReadByte()
	case "short":
		return d.Reader.ReadShort()
	case "int":
		return d.Reader.ReadInt()
	case "long":
		return d.Reader.ReadLong()
	case "float":
		return d.Reader.ReadFloat()
	case "double":
		return d.Reader.ReadDouble()
	default:
		return d.readObject0()
	}
}

// DefaultReadObject Ref:ObjectInputStream.defaultReadObject()
func (d *JavaDeserializer) DefaultReadObject() error {
	d.SetBlkMode(false)
	err := d.defaultReadFields(d.CurObj)
	d.SetBlkMode(true)
	return err
}

func (js *JavaDeserializer) SetBlkMode(newMode bool) bool {
	if newMode == js.Reader.blockMode {
		return newMode
	}
	if newMode {
		_, err := js.Reader.readBlockData()
		if err != nil {
			panic(err)
		}
	}
	js.Reader.blockMode = newMode
	return newMode
}

func (js *JavaDeserializer) ReadObject() (interface{}, error) {
	object, err := js.readObject0()
	return object, err
}

func (js *JavaDeserializer) ReadPrimitiveArray(desc java.Descriptor) (interface{}, error) {
	dim := strings.Count(string(desc), "[]")
	typeStr := strings.ReplaceAll(string(desc), "[]", "")
	elemType := PrimitiveArrayTypeMap[typeStr]
	// 递归创建多维数组
	length, err := js.Reader.ReadInt()
	if err != nil {
		return nil, err
	}
	arr, err := js.createArray(elemType, dim, int(length), false)
	if err != nil {
		return nil, err
	}
	return arr, nil
}

func (js *JavaDeserializer) createArray(elemType reflect.Type, dim, length int, empty bool) (interface{}, error) {

	// 创建当前维度切片
	sliceType := reflect.SliceOf(elemType)
	if dim > 1 {
		// 创建多维数组,readObject读取本维度的数据
		//arr := reflect.MakeSlice(sliceType, int(length), int(length))
		subType, err := js.createArray(elemType, dim-1, length, true)
		if err != nil {
			return nil, err
		}
		sliceType = reflect.SliceOf(reflect.TypeOf(subType))
	}

	arr := reflect.MakeSlice(sliceType, int(length), int(length))
	if empty {
		return arr.Interface(), nil
	}
	// 填充数组数据
	for i := 0; i < length; i++ {
		if dim == 1 {
			// 基本类型元素
			val, err := js.readPrimitive(elemType)
			if err != nil {
				return nil, err
			}
			arr.Index(i).Set(reflect.ValueOf(val))
		} else {
			// 递归处理子数组
			subArr, err := js.readObject0()
			if err != nil {
				return nil, err
			}
			arr.Index(i).Set(reflect.ValueOf(subArr))
		}
	}
	return arr.Interface(), nil
}

// 读取基本类型值
func (js *JavaDeserializer) readPrimitive(t reflect.Type) (interface{}, error) {
	switch t.Kind() {
	case reflect.Int32: // int
		return js.Reader.ReadInt()
	case reflect.Int16: // short
		return js.Reader.ReadShort()
	case reflect.Int64: // long
		return js.Reader.ReadLong()
	case reflect.Float32: // float
		return js.Reader.ReadFloat()
	case reflect.Float64: // double
		return js.Reader.ReadDouble()
	case reflect.Uint16: // char
		return js.Reader.ReadShort()
	case reflect.Bool: // boolean
		return js.Reader.ReadBool()
	case reflect.Uint8: // byte
		return js.Reader.ReadByte()
	default:
		return nil, fmt.Errorf("unsupported type: %s", t)
	}
}
