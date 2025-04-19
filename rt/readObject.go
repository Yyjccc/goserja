package rt

import (
	"errors"
	"goserja/impl"
	"goserja/java"
	"math"
)

func init() {
	loader := java.GetContextClassLoader()

	// TemplatesImpl

	loader.RegisterReadObject(func(ser interface{}, obj *java.Object) error {
		deserializer := ser.(*impl.JavaDeserializer)

		err := deserializer.DefaultReadObject()
		_, err = deserializer.Reader.ReadBool()
		return err
	}, java.TemplatesImplClass.Name)

	// HashMap
	loader.RegisterReadObject(func(ser interface{}, obj *java.Object) error {
		deserializer := ser.(*impl.JavaDeserializer)
		if err := deserializer.DefaultReadObject(); err != nil {
			return err
		}
		if _, err := deserializer.Reader.ReadInt(); err != nil {
			return err
		}
		mappings, err := deserializer.Reader.ReadInt()
		if err != nil {
			return err
		}
		capVal := 0
		if mappings < 0 {
			return errors.New("Illegal mappings count on readObject HashMap.")
		} else if mappings > 0 {
			lf := math.Min(math.Max(0.25, float64(loadFactor)), 4.0)
			fc := float64(mappings)/lf + 1.0

			if fc < initialCapacity {
				capVal = initialCapacity
			} else {
				if fc > MAXIMUM_CAPACITY {
					capVal = MAXIMUM_CAPACITY
				} else {
					capVal = tableSizeFor(int(fc))
				}
			}
			ft := float64(capVal) * lf
			threshold := 0
			if capVal < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY {
				threshold = int(ft)
			} else {
				threshold = 0x7fffffff
			}
			obj.Fields["threshold"] = threshold
		}
		tab := make([]*java.Object, capVal)
		obj.Fields["tab"] = tab
		obj.Fields["size"] = 0
		hashMap := &HashMap{
			Object:   *obj,
			Capacity: capVal,
		}
		obj.Extend = hashMap
		for i := 0; i < int(mappings); i++ {
			key, err := deserializer.ReadObject()
			if err != nil {
				return err
			}
			value, err := deserializer.ReadObject()
			if err != nil {
				return err
			}
			hashMap.Put(key, value)
		}

		return nil
	}, java.HashMapClass.Name)

	loader.RegisterReadObject(func(ser interface{}, obj *java.Object) error {
		deserializer := ser.(*impl.JavaDeserializer)
		if err := deserializer.DefaultReadObject(); err != nil {
			return err
		}
		if _, err := deserializer.Reader.ReadInt(); err != nil {
			return err
		}
		pq := &PriorityQueue{
			Object:   *obj,
			Capacity: initialCapacity,
		}
		obj.Extend = pq

		size := int(obj.Fields["size"].(int32))
		queue := make([]java.Object, initialCapacity)
		obj.Fields["queue"] = queue
		obj.Fields["size"] = 0
		obj.Fields["modCount"] = 0
		for i := 0; i < size; i++ {
			val, err := deserializer.ReadObject()
			if err != nil {
				return err
			}

			pq.Add(*(val.(*java.Object)))
		}
		return nil
	}, java.PriorityQueueClass.Name)
}
