package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $CLANG -strip $LLVM_STRIP -target bpfel Bpf analyzer.c -- -I./includes
