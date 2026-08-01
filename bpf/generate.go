package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel Bpf analyzer.c -- -I./headers
