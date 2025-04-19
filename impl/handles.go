package impl

import (
	"goserja/java"
	"reflect"
	"unsafe"
)

/**
引用处理, ObjectOutputStream$HandleTable 实现
*/

//维护对象引用

// HandleTable 轻量级身份哈希表
type HandleTable struct {
	size       int           // 当前存储的对象数量
	threshold  int           // 触发扩容的阈值
	loadFactor float64       // 负载因子
	spine      []int         // 哈希桶：对象哈希值 -> 句柄
	next       []int         // 解决哈希冲突
	objs       []interface{} // 存储对象本身
}

// NewHandleTable 创建一个 HandleTable
func NewHandleTable(initialCapacity int, loadFactor float64) *HandleTable {
	ht := &HandleTable{
		loadFactor: loadFactor,
		spine:      make([]int, initialCapacity),
		next:       make([]int, initialCapacity),
		objs:       make([]interface{}, initialCapacity),
		threshold:  int(float64(initialCapacity) * loadFactor),
	}

	ht.clear()
	return ht
}

// Assign 为对象分配句柄
func (ht *HandleTable) Assign(obj interface{}) int {
	if ht.size >= len(ht.next) {
		ht.growEntries()
	}
	if ht.size >= ht.threshold {
		ht.growSpine()
	}
	ht.insert(obj, ht.size)
	ht.size++
	return ht.size - 1
}

// Lookup 查询对象对应的句柄
func (ht *HandleTable) Lookup(obj interface{}) int {
	if o, ok := obj.(java.Object); ok {
		obj = o.UnWrap()
	}
	if ht.size == 0 {
		return -1
	}
	//index := Hash(obj) % len(ht.spine)
	//for i := ht.spine[index]; i >= 0; i = ht.next[i] {
	//	//if ht.objs[i] == obj {
	//	//	return i
	//	//}
	//	tmp := ht.objs[i]
	//	if reflect.DeepEqual(tmp, obj) {
	//		return i
	//	}
	//}
	for i, tmp := range ht.objs {
		if DeepEqual(tmp, obj) {
			return i
		}
	}

	//if reflect.DeepEqual(tmp, obj) {
	//	return i
	//}
	return -1
}

// Clear 清空表
func (ht *HandleTable) Clear() {
	ht.clear()
}

// 获取当前存储的对象数量
func (ht *HandleTable) Size() int {
	return ht.size
}

// 插入对象到哈希表
func (ht *HandleTable) insert(obj interface{}, handle int) {
	if o, ok := obj.(java.Object); ok {
		//不插入null
		if o.Descriptor == "null" {
			return
		}
		obj = o.UnWrap()

	}
	index := Hash(obj) % len(ht.spine)
	ht.objs[handle] = obj
	ht.next[handle] = ht.spine[index]
	//ht.spine[index] = handle
}

// 扩展哈希表容量
func (ht *HandleTable) growSpine() {
	newSpine := make([]int, (len(ht.spine)<<1)+1)
	ht.threshold = int(float64(len(newSpine)) * ht.loadFactor)
	for i := range newSpine {
		newSpine[i] = -1
	}
	ht.spine = newSpine

	// 重新插入所有对象
	for i := 0; i < ht.size; i++ {
		ht.insert(ht.objs[i], i)
	}
}

// 扩展对象存储容量
func (ht *HandleTable) growEntries() {
	newLength := (len(ht.next) << 1) + 1
	newNext := make([]int, newLength)
	copy(newNext, ht.next)
	ht.next = newNext

	newObjs := make([]interface{}, newLength)
	copy(newObjs, ht.objs)
	ht.objs = newObjs
}

// 清空表
func (ht *HandleTable) clear() {
	for i := range ht.spine {
		ht.spine[i] = -1
	}
	for i := 0; i < ht.size; i++ {
		ht.objs[i] = nil
	}
	ht.size = 0
}

func (ht *HandleTable) LookupObject(handle int32) interface{} {
	val := ht.objs[handle]
	switch val.(type) {
	case string:
		str := java.NewString(val.(string))
		return &str
	case *java.Object:
		return val.(*java.Object)
	case *java.Class:
		return val
	case *LoadedClass:
		return &(val.(*LoadedClass).Class)

	default:
		panic("unsolved case in LookupObject")
	}
}

// 计算hash
func Hash(obj interface{}) int {
	if obj == nil {
		return 0
	}
	//ptr := reflect.ValueOf(obj).Pointer() // 获取对象的地址
	//return int(uintptr(ptr) & 0x7FFFFFFF) // 保持非负
	return int(uintptr(unsafe.Pointer(&obj))) & 0x7FFFFFFF
}

// 已加载的类对象 xxx.class
type LoadedClass struct {
	Class java.Class
}

/**

重写reflect.DeepEqual

*/

type visit struct {
	a1  unsafe.Pointer
	a2  unsafe.Pointer
	typ reflect.Type
}

// DeepEqual 深度比较两个对象，包括函数指针的比较
func DeepEqual(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == b
	}
	v1 := reflect.ValueOf(a)
	v2 := reflect.ValueOf(b)
	if v1.Type() != v2.Type() {
		return false
	}
	visited := make(map[visit]bool)
	return deepValueEqual(v1, v2, visited)
}

func deepValueEqual(v1, v2 reflect.Value, visited map[visit]bool) bool {
	if !v1.IsValid() || !v2.IsValid() {
		return v1.IsValid() == v2.IsValid()
	}

	if v1.Type() != v2.Type() {
		return false
	}

	// 处理循环引用
	hard := func(k reflect.Kind) bool {
		switch k {
		case reflect.Map, reflect.Slice, reflect.Ptr, reflect.Interface:
			return true
		default:
			return false
		}
	}

	if v1.CanAddr() && v2.CanAddr() && hard(v1.Kind()) {
		addr1 := unsafe.Pointer(v1.UnsafeAddr())
		addr2 := unsafe.Pointer(v2.UnsafeAddr())
		if uintptr(addr1) > uintptr(addr2) {
			// 保证顺序一致，减少存入 visited 的次数
			addr1, addr2 = addr2, addr1
		}

		typ := v1.Type()
		v := visit{addr1, addr2, typ}
		if visited[v] {
			return true
		}
		visited[v] = true
	}

	switch v1.Kind() {
	case reflect.Func:
		if v1.IsNil() && v2.IsNil() {
			return true
		}
		if !v1.IsNil() && !v2.IsNil() {
			return v1.Pointer() == v2.Pointer()
		}
		return false
	case reflect.Ptr:
		//return true
		return deepValueEqual(v1.Elem(), v2.Elem(), visited)
	case reflect.Interface:
		return deepValueEqual(v1.Elem(), v2.Elem(), visited)
	case reflect.Struct:
		for i, n := 0, v1.NumField(); i < n; i++ {
			if !deepValueEqual(v1.Field(i), v2.Field(i), visited) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if v1.IsNil() != v2.IsNil() {
			return false
		}
		if v1.Len() != v2.Len() {
			return false
		}
		for i := 0; i < v1.Len(); i++ {
			if !deepValueEqual(v1.Index(i), v2.Index(i), visited) {
				return false
			}
		}
		return true
	case reflect.Array:
		for i := 0; i < v1.Len(); i++ {
			if !deepValueEqual(v1.Index(i), v2.Index(i), visited) {
				return false
			}
		}
		return true
	case reflect.Map:
		if v1.IsNil() != v2.IsNil() {
			return false
		}
		if v1.Len() != v2.Len() {
			return false
		}
		for _, key := range v1.MapKeys() {
			val1 := v1.MapIndex(key)
			val2 := v2.MapIndex(key)
			if !val2.IsValid() || !deepValueEqual(val1, val2, visited) {
				return false
			}
		}
		// 检查v2的键是否都在v1中
		for _, key := range v2.MapKeys() {
			val1 := v1.MapIndex(key)
			if !val1.IsValid() {
				return false
			}
		}
		return true
	case reflect.Bool:
		return v1.Bool() == v2.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v1.Int() == v2.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v1.Uint() == v2.Uint()
	case reflect.Float32, reflect.Float64:
		return v1.Float() == v2.Float()
	case reflect.String:
		return v1.String() == v2.String()
	case reflect.Complex64, reflect.Complex128:
		return v1.Complex() == v2.Complex()
	case reflect.Chan, reflect.UnsafePointer:
		return v1.Pointer() == v2.Pointer()
	default:
		return v1.Kind() == v2.Kind()
	}
}
