package impl

import "bufio"

type Deserializer struct {
	reader *bufio.Reader
	handles *HandleTable
}