package impl

import (
	"bytes"
	"encoding/binary"
)

// DataWriter 负责数据写入
type DataWriter struct {
	buffer *bytes.Buffer
}

func NewDataWriter() *DataWriter {
	return &DataWriter{
		buffer: bytes.NewBuffer(nil),
	}
}

func (dw *DataWriter) WriteByte(b byte) {
	dw.buffer.WriteByte(b)
}

func (dw *DataWriter) WriteUint16(v uint16) {
	binary.Write(dw.buffer, binary.BigEndian, v)
}

func (dw *DataWriter) WriteUint32(v uint32) {
	binary.Write(dw.buffer, binary.BigEndian, v)
}

func (dw *DataWriter) WriteUint64(v uint64) {
	binary.Write(dw.buffer, binary.BigEndian, v)
}

func (dw *DataWriter) WriteInt(v int32) {
	binary.Write(dw.buffer, binary.BigEndian, v)
}
func (dw *DataWriter) WriteString(s string) {
	dw.WriteUint16(uint16(len(s)))
	dw.buffer.WriteString(s)
}

func (dw *DataWriter) WriteBytes(data []byte) {
	dw.buffer.Write(data)
}

func (dw *DataWriter) Bytes() []byte {
	return dw.buffer.Bytes()
}
