# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

# 修改 APP 为新的基础文件名
APP := afp

BPF_OBJ := $(APP).bpf.o
OBJ := $(APP).o

# 使用 bpftool 生成 vmlinux.h 以支持 CO-RE
VMLINUX_H := vmlinux.h

# C 编译标志
# -I. 表示在当前目录查找头文件 (为了 vmlinux.h)
CFLAGS += -g -Wall -I.

# 链接库
LDLIBS = -lbpf -lelf

#LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
#LIBBPF_LDLIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

all: $(APP) $(BPF_OBJ)

# 规则：从 BPF 对象文件生成 skeleton 头文件
$(APP).skel.h: $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 规则：编译 BPF C 代码
$(BPF_OBJ): %.bpf.o: %.bpf.c $(VMLINUX_H)
	clang -g -O2 -target bpf \
	-c $(patsubst %.bpf.o,%.bpf.c,$@) -o $@

# 规则：编译用户态 C 代码
$(OBJ): %.o: %.c $(APP).skel.h
	clang $(CFLAGS) -c $< -o $@

# 规则：链接最终的可执行文件
$(APP): $(APP).c $(APP).skel.h
	$(CC) $< -o $@ -lbpf -lelf -lz -lzstd -static

# 规则：生成 vmlinux.h
# 这个目标依赖于内核的 BTF 信息，如果不存在会报错
$(VMLINUX_H):
	bpftool btf dump file ../vmlinux format c > $(VMLINUX_H)

clean:
	rm -f $(APP) $(OBJ) $(BPF_OBJ) $(APP).skel.h $(VMLINUX_H)

scp: $(APP) $(BPF_OBJ)
	scp $(APP) v22:~/
	scp $(BPF_OBJ) v22:~/

.PHONY: all clean scp
