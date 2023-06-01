package kinds

import (
	"sync"
)

type Set[T comparable] struct {
	Data map[T]struct{}
	lock sync.RWMutex
}

// 新建客户端
func NewSet[T comparable](strs ...T) *Set[T] {
	list := &Set[T]{Data: map[T]struct{}{}}
	for _, str := range strs {
		list.Add(str)
	}
	return list
}

// 添加元素
func (obj *Set[T]) Add(value T) {
	obj.lock.Lock()
	obj.Data[value] = struct{}{}
	obj.lock.Unlock()
}

// 删除元素
func (obj *Set[T]) Del(value T) bool {
	obj.lock.Lock()
	delete(obj.Data, value)
	obj.lock.Unlock()
	return false
}

// 判断元素是否存在
func (obj *Set[T]) Has(value T) bool {
	obj.lock.RLock()
	_, ok := obj.Data[value]
	obj.lock.RUnlock()
	return ok
}

// 返回元素长度
func (obj *Set[T]) Len() int {
	return len(obj.Data)
}

// 重置
func (obj *Set[T]) ReSet() {
	obj.Data = make(map[T]struct{})
}

// 返回数组
func (obj *Set[T]) Array() []T {
	result := make([]T, obj.Len())
	var i int
	for val := range obj.Data {
		result[i] = val
		i++
	}
	return result
}
