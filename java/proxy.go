package java

func NewProxyObject(handle Object, ifs []Interface) *Object {
	class := &Class{
		Name:             "java.lang.Proxy$$",
		IsProxy:          true,
		Super:            ProxyClass.Name,
		SerialVersionUID: 0,
		ProxyInterface:   ifs,
		Implements:       make([]Interface, 0),
		Fields:           make([]Field, 0),
	}
	instance := class.newInstance(nil)
	instance.Fields["h"] = handle
	return &instance
}
