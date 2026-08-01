/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2026 Namex IXP. All rights reserved.
 *
 * Author: Francesco Ferreri <f.ferreri@namex.it>
 * GitHub: @vajra77
 */

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $CLANG -strip $LLVM_STRIP -target bpfel Bpf analyzer.c  -- -I./includes
