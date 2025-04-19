package impl

import (
	"bytes"
	"encoding/binary"
	"math"
)

const MAX_BLOCK_SIZE = 1024

// BlockDataWriter 封装了块模式下的写入操作。
// 当 blockMode 为 true 时，数据先写入 blockBuffer，达到一定大小后（或手动 flush）
// 将数据分块写入到底层 DataWriter 中，并在每个数据块前写入块头、最后写入块结束标识。
type BlockDataWriter struct {
	underlying  *DataWriter   // 底层写入流
	blockBuffer *bytes.Buffer // 块模式下的临时缓冲区
	blockMode   bool          // 是否启用块模式
}

// NewBlockDataWriter 构造函数，传入底层流（io.Writer）以及是否启用块模式
func NewBlockDataWriter(blockMode bool) *BlockDataWriter {
	// 封装底层流到 DataWriter 中
	return &BlockDataWriter{
		underlying:  &DataWriter{buffer: bytes.NewBuffer(nil)},
		blockBuffer: bytes.NewBuffer(make([]byte, 0, 1024)),
		blockMode:   blockMode,
	}
}

// WriteBytes 写入字节切片，逻辑同 WriteByte
func (bdw *BlockDataWriter) WriteBytes(data []byte) {
	if bdw.blockMode {
		bdw.blockBuffer.Write(data)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteBytes(data)
	}
}

// writeBlockHeader 根据当前块长度写入块头
// 如果 length <= 0xFF，则写入短块头：TC_BLOCKDATA + 1 字节长度；
// 否则写入长块头：TC_BLOCKDATALONG + 4 字节长度（一般此处不会发生，因为 MAX_BLOCK_SIZE=255）。
func (bdw *BlockDataWriter) writeBlockHeader(length int) {
	if length <= 0xFF {
		bdw.underlying.WriteByte(TC_BLOCKDATA)
		bdw.underlying.WriteByte(byte(length))
	} else {
		bdw.underlying.WriteByte(TC_BLOCKDATALONG)
		bdw.underlying.WriteUint32(uint32(length))
	}
}

// flushBlockBuffer 将 blockBuffer 中的数据分块写入到底层流。
// 每块最多写入 MAX_BLOCK_SIZE 字节，然后写入块结束标识 TC_ENDBLOCKDATA。
func (bdw *BlockDataWriter) flushBlockBuffer() {
	if bdw.blockBuffer.Len() == 0 {
		return
	}
	// 循环处理 blockBuffer 中的数据，分块写入
	for bdw.blockBuffer.Len() > 0 {
		chunkSize := bdw.blockBuffer.Len()
		if chunkSize > MAX_BLOCK_SIZE {
			chunkSize = MAX_BLOCK_SIZE
		}
		// 写入块头（写入当前块的长度）
		bdw.writeBlockHeader(chunkSize)
		// 从 blockBuffer 读取 chunkSize 字节并写入到底层流
		chunk := bdw.blockBuffer.Next(chunkSize)
		bdw.underlying.WriteBytes(chunk)
	}
	// 最后写入块结束标识
	//bdw.underlying.WriteByte(TC_ENDBLOCKDATA)
}

// Flush 手动刷新，将 blockBuffer 中剩余的数据分块写入到底层流
func (bdw *BlockDataWriter) Flush() {
	bdw.flushBlockBuffer()
}

// Bytes 返回最终写入底层流的数据
func (bdw *BlockDataWriter) Bytes() []byte {
	// 确保刷新所有块数据
	bdw.Flush()
	return bdw.underlying.Bytes()
}

func (bdw *BlockDataWriter) WriteByte(b byte) {
	if bdw.blockMode {
		bdw.blockBuffer.WriteByte(b)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteByte(b)
	}
}

func (bdw *BlockDataWriter) WriteUint16(v uint16) {
	if bdw.blockMode {
		binary.Write(bdw.blockBuffer, binary.BigEndian, v)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteUint16(v)
	}
}

func (bdw *BlockDataWriter) WriteUint32(v uint32) {
	if bdw.blockMode {
		binary.Write(bdw.blockBuffer, binary.BigEndian, v)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteUint32(v)
	}
}

func (bdw *BlockDataWriter) WriteUint64(v uint64) {
	if bdw.blockMode {
		binary.Write(bdw.blockBuffer, binary.BigEndian, v)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteUint64(v)
	}
}

func (bdw *BlockDataWriter) WriteInt(v int32) {
	if bdw.blockMode {
		binary.Write(bdw.blockBuffer, binary.BigEndian, v)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteInt(v)
	}
}

func (bdw *BlockDataWriter) WriteString(s string) {
	if bdw.blockMode {
		// 先写入字符串长度（uint16），再写入字符串内容
		bdw.WriteUint16(uint16(len(s)))
		bdw.blockBuffer.WriteString(s)
		if bdw.blockBuffer.Len() >= MAX_BLOCK_SIZE {
			bdw.flushBlockBuffer()
		}
	} else {
		bdw.underlying.WriteString(s)
	}
}

func (bdw *BlockDataWriter) WriteFloat32(v float32) {
	bits := math.Float32bits(v)
	bdw.WriteUint32(bits)
}

func (bdw *BlockDataWriter) WriteFloat64(v float64) {
	bits := math.Float64bits(v)
	bdw.WriteUint64(bits)
}
