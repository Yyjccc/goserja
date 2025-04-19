package rt

import (
	"goserja/impl"
	"goserja/java"
)

func init() {
	loader := java.GetContextClassLoader()
	TemplatesImplWriteObject := func(ser interface{}, obj *java.Object) {
		serializer := ser.(*impl.JavaSerializer)
		serializer.DefaultWriteObject(obj)
		////写入 _transletIndex
		//serializer.WriteInt(-1)
		////写入 _indentNumber
		//serializer.WriteInt(0)
		serializer.WriteBoolean(false)
	}
	java.TemplatesImplClass.WriteObjectData = TemplatesImplWriteObject
	loader.RegisterWriteObject(TemplatesImplWriteObject, java.TemplatesImplClass.Name)

	HashMapWriteObject := func(ser interface{}, obj *java.Object) {
		serializer := ser.(*impl.JavaSerializer)
		serializer.DefaultWriteObject(obj)
		hashMap := obj.Extend.(*HashMap)
		//写入容量
		serializer.GetWriter().WriteInt(int32(hashMap.Capacity))
		//写入size
		size := obj.Fields["size"].(int)
		serializer.GetWriter().WriteInt(int32(size))
		serializer.SetBlkMode(false)
		//遍历hash表+链表节点
		tab := obj.Fields["tab"].([]*java.Object)
		for _, node := range tab {
			if node == nil {
				continue
			}
			for node != nil {
				key := node.Fields["key"]
				value := node.Fields["value"]
				serializer.WriteAllTypeData(key, nil)
				serializer.WriteAllTypeData(value, nil)
				node = node.Fields["next"].(*java.Object)
			}
		}
	}
	loader.RegisterWriteObject(HashMapWriteObject, java.HashMapClass.Name)
	java.HashMapClass.WriteObjectData = HashMapWriteObject

	//PriorityQueue
	PriorityQueueWriteObject := func(ser interface{}, obj *java.Object) {
		serializer := ser.(*impl.JavaSerializer)
		serializer.DefaultWriteObject(obj)
		//write size
		pq := obj.Extend.(*PriorityQueue)
		serializer.WriteInt(pq.GetSize())
		serializer.SetBlkMode(false)
		queue := obj.Fields["queue"].([]java.Object)
		for _, node := range queue {
			if node.GetClass() == nil {
				continue
			}
			serializer.WriteAllTypeData(node, nil)
		}
	}
	loader.RegisterWriteObject(PriorityQueueWriteObject, java.PriorityQueueClass.Name)
	java.PriorityQueueClass.WriteObjectData = PriorityQueueWriteObject
}
