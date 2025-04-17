package rt

import (
	"goserja/java"
)

//HashMap方法实现

// 默认初始容量
const initialCapacity = 16
const loadFactor = float32(0.75)

type HashMap struct {
	java.Object
	Capacity int
}

func NewJHashMap() HashMap {
	hashMap := HashMap{
		Object:   java.HashMapClass.NewInstance(nil),
		Capacity: initialCapacity,
	}
	hashMap.Fields["threshold"] = int(float32(initialCapacity) * loadFactor)
	hashMap.Fields["loadFactor"] = loadFactor
	tabVal := make([]*java.Object, initialCapacity)
	hashMap.Fields["tab"] = tabVal
	hashMap.Extend = &hashMap
	return hashMap
}

// 计算 hash 值
func hash(key interface{}) int {
	if s, ok := key.(string); ok {
		h := 0
		for _, c := range s {
			h = 31*h + int(c)
		}
		return h
	}
	//忽略其他情况
	return 1
}

// 计算大于等于指定值的最小 2 的幂
func tableSizeFor(cap int) int {
	n := cap - 1
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

// 扩容 HashMap
func (hm *HashMap) resize() {
	newCapacity := hm.Capacity * 2
	newBuckets := make([]java.Object, newCapacity)
	tab := hm.Fields["tab"].([]java.Object)
	for _, node := range tab {
		for node.Fields["next"] != nil {
			index := hash(node.Fields["key"]) & (newCapacity - 1)
			newNode := java.HashMap_NodeClass.NewInstance(nil)
			newNode.Fields["key"] = node.Fields["key"]
			newNode.Fields["value"] = node.Fields["value"]
			newNode.Fields["next"] = newBuckets[index]
			newBuckets[index] = newNode
			node = node.Fields["next"].(java.Object)
		}
	}

	hm.Fields["tab"] = newBuckets
	hm.Capacity = newCapacity
	hm.Fields["threshold"] = int(float32(newCapacity) * loadFactor)
}

// 插入键值对
func (hm *HashMap) Put(key interface{}, value any) {
	if hm.Fields["size"].(int) >= hm.Fields["threshold"].(int) {
		hm.resize()
	}
	index := hash(key) & (hm.Capacity - 1)
	tab := hm.Fields["tab"].([]*java.Object)
	node := tab[index]
	// 检查是否存在相同 key
	for node != nil {
		if node.Fields["key"] == key {
			node.Fields["value"] = value
			return
		}
		node = node.Fields["next"].(*java.Object)
	}
	// 插入新节点
	newNode := java.HashMap_NodeClass.NewInstance(nil)
	newNode.Fields["key"] = key
	newNode.Fields["value"] = value
	newNode.Fields["next"] = tab[index]
	tab[index] = &newNode
	i := hm.Fields["size"].(int)
	hm.Fields["size"] = i + 1
}

// 获取值
func (hm *HashMap) Get(key interface{}) (any, bool) {
	index := hash(key) & (hm.Capacity - 1)
	tab := hm.Fields["tab"].([]*java.Object)
	node := tab[index]

	for node != nil {
		if node.Fields["key"] == key {
			return node.Fields["value"], true
		}
		node = node.Fields["next"].(*java.Object)
	}
	return nil, false
}
