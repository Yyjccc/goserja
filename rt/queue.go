package rt

/*
	java优先队列封装
*/

import (
	"goserja/java"
)

// PriorityQueue 实现
const defaultCapacity = 11

type PriorityQueue struct {
	java.Object
	Capacity int
}

func NewJPriorityQueue() PriorityQueue {
	pq := PriorityQueue{
		Object:   java.LoadClass(java.PriorityQueueClass.Name).NewInstance(nil),
		Capacity: defaultCapacity,
	}
	pq.Fields["size"] = 0
	pq.Fields["modCount"] = 0
	pq.Fields["queue"] = make([]java.Object, defaultCapacity)
	pq.Fields["comparator"] = nil // Java 的 PriorityQueue 允许自定义 Comparator
	pq.Extend = &pq
	return pq
}

func (pq *PriorityQueue) Add(element java.Object) {
	pq.offer(element)
}

// 插入元素
func (pq *PriorityQueue) offer(element java.Object) {
	queue := pq.Fields["queue"].([]java.Object)
	size := pq.Fields["size"].(int)
	if size >= pq.Capacity {
		pq.resize()
	}
	queue[size] = element
	pq.Fields["size"] = size + 1
	pq.Fields["modCount"] = pq.Fields["modCount"].(int) + 1
	pq.siftUp(size)
}

// 获取并删除队列头部元素
func (pq *PriorityQueue) Poll() (interface{}, bool) {
	size := pq.Fields["size"].(int)
	if size == 0 {
		return nil, false
	}
	queue := pq.Fields["queue"].([]java.Object)
	element := queue[0]
	queue[0] = queue[size-1]
	queue[size-1] = java.NULL
	pq.Fields["size"] = size - 1
	pq.Fields["modCount"] = pq.Fields["modCount"].(int) + 1
	pq.siftDown(0)
	return element, true
}

// 获取但不删除队列头部元素
func (pq *PriorityQueue) Peek() (interface{}, bool) {
	if pq.Fields["size"].(int) == 0 {
		return nil, false
	}
	queue := pq.Fields["queue"].([]java.Object)
	return queue[0], true
}

// 调整队列（上移）
func (pq *PriorityQueue) siftUp(index int) {
	queue := pq.Fields["queue"].([]java.Object)
	for index > 0 {
		parent := (index - 1) / 2
		if pq.compare(queue[index], queue[parent]) >= 0 {
			break
		}
		queue[index], queue[parent] = queue[parent], queue[index]
		index = parent
	}
}

// 调整队列（下移）
func (pq *PriorityQueue) siftDown(index int) {
	size := pq.Fields["size"].(int)
	queue := pq.Fields["queue"].([]java.Object)
	for 2*index+1 < size {
		left := 2*index + 1
		right := 2*index + 2
		smallest := left
		if right < size && pq.compare(queue[right], queue[left]) < 0 {
			smallest = right
		}
		if pq.compare(queue[index], queue[smallest]) <= 0 {
			break
		}
		queue[index], queue[smallest] = queue[smallest], queue[index]
		index = smallest
	}
}

// 比较两个元素
func (pq *PriorityQueue) compare(a, b interface{}) int {
	return -1
}

// 扩容
func (pq *PriorityQueue) resize() {
	newCapacity := pq.Capacity * 2
	newQueue := make([]*java.Object, newCapacity)
	copy(newQueue, pq.Fields["queue"].([]*java.Object))
	pq.Fields["queue"] = newQueue
	pq.Capacity = newCapacity
}

func (pq *PriorityQueue) SetComparator(comparator java.Object) {
	pq.Fields["comparator"] = comparator
}

func (pq *PriorityQueue) GetSize() int {
	size := pq.Fields["size"].(int)
	if size+1 > 2 {
		return size + 1
	}
	return 2
}
