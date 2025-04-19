package impl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	ErrInsufficientData = errors.New("insufficient data")
	ErrInvalidUTF       = errors.New("invalid modified UTF-8 encoding")
)

type SerializeReader struct {
	buffer *bytes.Reader
	len    int
	pos    int
}

func (r *SerializeReader) Read(p []byte) (n int, err error) {
	return r.buffer.Read(p)
}

func NewDataReader(data []byte) *SerializeReader {
	return &SerializeReader{
		buffer: bytes.NewReader(data),
		len:    len(data),
		pos:    0,
	}
}

// 基础操作方法
func (r *SerializeReader) Pos() int {
	return r.pos
}

func (r *SerializeReader) Remaining() int {
	return r.len - r.pos
}

func (r *SerializeReader) Seek(n int) error {
	_, err := r.buffer.Seek(int64(n), io.SeekStart)
	if err == nil {
		r.pos = n
	}
	return err
}

func (r *SerializeReader) peek() (byte, error) {
	// 保存当前读取位置
	originalPos, err := r.buffer.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	// 尝试读取一个字节
	b, err := r.buffer.ReadByte()
	if err != nil {
		// 即使出错也要还原位置
		r.buffer.Seek(originalPos, io.SeekStart)
		return 0, err
	}
	// 还原到原始读取位置（注意ReadByte会使位置+1）
	_, err = r.buffer.Seek(originalPos, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return b, nil
}

// 读取单个字节
func (r *SerializeReader) ReadByte() (byte, error) {
	if r.Remaining() < 1 {
		return 0, ErrInsufficientData
	}
	b, err := r.buffer.ReadByte()
	if err == nil {
		r.pos++
	}
	return b, err
}

// 读取布尔值
func (r *SerializeReader) ReadBool() (bool, error) {
	b, err := r.ReadByte()
	return b != 0, err
}

// 读取大端序16位整数 (short)
func (r *SerializeReader) ReadShort() (int16, error) {
	if r.Remaining() < 2 {
		return 0, ErrInsufficientData
	}
	var v uint16
	err := binary.Read(r.buffer, binary.BigEndian, &v)
	if err == nil {
		r.pos += 2
	}
	return int16(v), err
}

// 读取大端序32位整数 (int)
func (r *SerializeReader) ReadInt() (int32, error) {
	if r.Remaining() < 4 {
		return 0, ErrInsufficientData
	}
	var v int32
	err := binary.Read(r.buffer, binary.BigEndian, &v)
	if err == nil {
		r.pos += 4
	}
	return v, err
}

// 读取大端序64位整数 (long)
func (r *SerializeReader) ReadLong() (int64, error) {
	if r.Remaining() < 8 {
		return 0, ErrInsufficientData
	}
	var v uint64
	err := binary.Read(r.buffer, binary.BigEndian, &v)
	if err == nil {
		r.pos += 8
	}
	return int64(v), err
}

// 读取大端序32位浮点数 (float)
func (r *SerializeReader) ReadFloat() (float32, error) {
	v, err := r.ReadInt()
	return math.Float32frombits(uint32(v)), err
}

// 读取大端序64位浮点数 (double)
func (r *SerializeReader) ReadDouble() (float64, error) {
	v, err := r.ReadLong()
	return math.Float64frombits(uint64(v)), err
}

// 读取Java修改版UTF-8字符串
func (r *SerializeReader) ReadUTF() (string, error) {
	length, err := r.ReadShort()
	if err != nil {
		return "", err
	}
	if length < 0 {
		return "", ErrInvalidUTF
	}

	data := make([]byte, length)
	n, err := io.ReadFull(r.buffer, data)
	r.pos += n
	if err != nil {
		return "", err
	}

	// Java的modified UTF-8处理
	return decodeModifiedUTF8(data)
}

// 读取指定长度的字节数组
func (r *SerializeReader) ReadFully(buf []byte) error {
	if r.Remaining() < len(buf) {
		return ErrInsufficientData
	}
	n, err := io.ReadFull(r.buffer, buf)
	r.pos += n
	return err
}

// 解码Java modified UTF-8
func decodeModifiedUTF8(data []byte) (string, error) {
	var runes []rune
	for i := 0; i < len(data); {
		b := data[i]
		switch {
		case b&0x80 == 0x00: // 1字节
			runes = append(runes, rune(b))
			i++
		case b&0xE0 == 0xC0: // 2字节
			if i+1 >= len(data) {
				return "", ErrInvalidUTF
			}
			runes = append(runes, rune(b&0x1F)<<6|rune(data[i+1]&0x3F))
			i += 2
		case b&0xF0 == 0xE0: // 3字节
			if i+2 >= len(data) {
				return "", ErrInvalidUTF
			}
			runes = append(runes, rune(b&0x0F)<<12|
				rune(data[i+1]&0x3F)<<6|
				rune(data[i+2]&0x3F))
			i += 3
		default:
			return "", ErrInvalidUTF
		}
	}
	return string(runes), nil
}

func (r *SerializeReader) ReadBytes(i int) ([]byte, error) {
	if i < 0 {
		return nil, errors.New("negative length")
	}

	// 创建目标缓冲区
	data := make([]byte, i)

	// 使用io.ReadFull确保读取完整数据
	n, err := io.ReadFull(r.buffer, data)
	r.pos += n // 更新已读取位置

	if err != nil {
		// 遇到错误时返回nil和错误（包括部分读取场景）
		return nil, err
	}

	return data, nil
}

func (r *SerializeReader) ReadLongUTF() (string, error) {
	utflen, err := r.ReadLong()
	if err != nil {
		return "", err
	}
	if utflen < 0 {
		return "", fmt.Errorf("invalid UTF length: %d", utflen)
	}
	// 2. 按长度读取所有 UTF-8 数据
	buf := make([]byte, utflen)
	if _, err := io.ReadFull(r.buffer, buf); err != nil {
		return "", err
	}
	// 3. 解码 Modified UTF‑8——可用第三方库
	return decodeModifiedUTF8(buf)
}

func (r *SerializeReader) ReadString() (string, error) {
	length, err := r.ReadShort()
	if err != nil {
		return "", err
	}
	if length < 0 {
		return "", ErrInvalidUTF
	}
	data := make([]byte, length)
	n, err := io.ReadFull(r.buffer, data)
	r.pos += n
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type BlockDataReader struct {
	underlying  *SerializeReader // 底层读入流
	blockBuffer *bytes.Buffer    // 块模式下的临时缓冲区
	blockMode   bool             // 是否启用块模式
	pos         int
}

func NewBlockDataReader(data []byte) *BlockDataReader {
	return &BlockDataReader{
		underlying:  NewDataReader(data),
		blockBuffer: bytes.NewBuffer(nil),
	}
}

func (b *BlockDataReader) readBlockData() (int, error) {
	b.blockBuffer.Reset()
	b.pos = 0
	read := 0
	defer func() { b.underlying.pos += read }()
	for {
		peek, err := b.underlying.peek()
		if err != nil {
			return 0, err
		}
		switch peek {
		case TC_BLOCKDATA:
			b.underlying.ReadByte()
			lenByte, err := b.underlying.ReadByte()
			if err != nil {
				return 0, err
			}
			data := make([]byte, lenByte)
			_, err = b.underlying.Read(data)
			if err != nil {
				return 0, err
			}
			b.blockBuffer.Write(data)
			read += int(lenByte)
			break
		case TC_BLOCKDATALONG:
			b.underlying.ReadByte()
			lengthByte, err := b.underlying.ReadInt()
			if err != nil {
				return 0, err
			}
			length := uint32(lengthByte)
			data := make([]byte, length)
			_, err = b.underlying.Read(data)
			if err != nil {
				return 0, err
			}
			b.blockBuffer.Write(data)
			read += int(length)
			break
		case TC_ENDBLOCKDATA:
			b.underlying.ReadByte()
			return read, nil
		default:
			return read, nil
		}
	}
}

func (b *BlockDataReader) ReadBool() (bool, error) {
	if b.blockMode {
		boolVal, err := b.blockBuffer.ReadByte()
		return boolVal != 0, err
	}
	return b.underlying.ReadBool()
}

func (b *BlockDataReader) ReadByte() (byte, error) {
	if b.blockMode {
		return b.blockBuffer.ReadByte()
	}
	return b.underlying.ReadByte()
}
func (b *BlockDataReader) Remaining() int {
	if b.blockMode {
		return b.blockBuffer.Len() - b.pos
	}
	return b.underlying.Remaining()
}
func (b *BlockDataReader) ReadShort() (int16, error) {
	if b.blockMode {
		if b.Remaining() < 2 {
			return 0, ErrInsufficientData
		}
		var v uint16
		err := binary.Read(b.blockBuffer, binary.BigEndian, &v)
		if err == nil {
			b.pos += 2
		}
		return int16(v), err
	}
	return b.underlying.ReadShort()
}

func (b *BlockDataReader) ReadLong() (int64, error) {
	if b.blockMode {
		if b.Remaining() < 8 {
			return 0, ErrInsufficientData
		}
		var v uint64
		err := binary.Read(b.blockBuffer, binary.BigEndian, &v)
		if err == nil {
			b.pos += 8
		}
		return int64(v), err
	}
	return b.underlying.ReadLong()
}

func (b *BlockDataReader) ReadInt() (int32, error) {
	if b.blockMode {
		var value int32
		err := binary.Read(b.blockBuffer, binary.BigEndian, &value)
		b.pos += 4
		return value, err
	}
	return b.underlying.ReadInt()
}

func (b *BlockDataReader) ReadFloat() (float32, error) {
	if b.blockMode {
		v, err := b.ReadInt()
		return math.Float32frombits(uint32(v)), err
	}
	return b.underlying.ReadFloat()
}

func (b *BlockDataReader) ReadDouble() (float64, error) {
	if b.blockMode {
		v, err := b.ReadLong()
		return math.Float64frombits(uint64(v)), err
	}
	return b.underlying.ReadDouble()
}

func (b *BlockDataReader) Peek() (byte, error) {
	if b.blockMode {
		c, err := b.blockBuffer.ReadByte()
		if err != nil {
			return 0, err
		}
		// 回退读取位置
		if err := b.blockBuffer.UnreadByte(); err != nil {
			return 0, err
		}
		return c, nil
	}
	return b.underlying.peek()
}

func (b *BlockDataReader) ReadUTF() (string, error) {
	if b.blockMode {
		length, err := b.ReadShort()
		if err != nil {
			return "", err
		}
		if length < 0 {
			return "", ErrInvalidUTF
		}

		data := make([]byte, length)
		n, err := io.ReadFull(b.blockBuffer, data)
		b.pos += n
		if err != nil {
			return "", err
		}
		// Java的modified UTF-8处理
		return decodeModifiedUTF8(data)
	}
	return b.underlying.ReadUTF()
}

func (b *BlockDataReader) ReadLongUTF() (string, error) {
	if b.blockMode {
		utflen, err := b.ReadLong()
		if err != nil {
			return "", err
		}
		if utflen < 0 {
			return "", fmt.Errorf("invalid UTF length: %d", utflen)
		}
		// 2. 按长度读取所有 UTF-8 数据
		buf := make([]byte, utflen)
		if _, err := io.ReadFull(b.blockBuffer, buf); err != nil {
			return "", err
		}
		// 3. 解码 Modified UTF‑8——可用第三方库
		return decodeModifiedUTF8(buf)
	}
	return b.underlying.ReadLongUTF()
}

func (b *BlockDataReader) ReadString() (string, error) {
	if b.blockMode {
		length, err := b.ReadShort()
		if err != nil {
			return "", err
		}
		if length < 0 {
			return "", ErrInvalidUTF
		}
		data := make([]byte, length)
		n, err := io.ReadFull(b.blockBuffer, data)
		b.pos += n
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return b.underlying.ReadString()
}
