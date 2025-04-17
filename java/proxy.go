package java

type ProxyObject struct {
	*Object
	Interfaces []Interface
}

func NewProxyObject(o *Object, ifs []Interface) *ProxyObject {
	o.isProxy = true
	return &ProxyObject{
		Object:     o,
		Interfaces: ifs,
	}
}
