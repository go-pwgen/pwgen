package pwgen

import (
	"io"
	"unsafe"
)

func PwRandomNumber(rand io.Reader, max int) (random int, err error) {
	if _, err = io.ReadFull(rand, unsafe.Slice((*byte)(unsafe.Pointer(&random)), int(unsafe.Sizeof(int(0))))); err != nil {
		return
	}
	random = int(uint(random) % uint(max))
	return
}

func PwRandomNumbers(rand io.Reader, max int, out []int) (err error) {
	if _, err = io.ReadFull(rand, unsafe.Slice((*byte)(unsafe.Pointer(&out[0])), len(out)*int(unsafe.Sizeof(int(0))))); err != nil {
		return
	}
	for i, v := range out {
		out[i] = int(uint(v) % uint(max))
	}
	return
}
