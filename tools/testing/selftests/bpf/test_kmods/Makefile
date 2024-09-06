TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(TEST_KMOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_test_no_cfi.ko bpf_test_modorder_x.ko \
	bpf_test_modorder_y.ko

$(foreach m,$(MODULES),$(eval obj-m += $(m:.ko=.o)))

CFLAGS_bpf_testmod_core.o = -I$(src)
bpf_testmod-y := bpf_testmod_core.o test_inlinable_kfuncs.o

all:
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) modules

clean:
	$(Q)$(MAKE) -C $(KDIR) M=$(TEST_KMOD_DIR) clean

ifdef CONFIG_CC_IS_CLANG

CLANG ?= $(LLVM_PREFIX)clang$(LLVM_SUFFIX)
LLC ?= $(LLVM_PREFIX)llc$(LLVM_SUFFIX)

CFLAGS_REMOVE_test_inlinable_kfuncs.bpf.bc.o += $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_test_inlinable_kfuncs.bpf.bc.o += $(PADDING_CFLAGS)
CFLAGS_test_inlinable_kfuncs.bpf.bc.o += -D__FOR_BPF
$(obj)/test_inlinable_kfuncs.bpf.bc.o: $(src)/test_inlinable_kfuncs.c
	$(Q)$(CLANG) $(c_flags) -emit-llvm -c $< -o $@

$(obj)/test_inlinable_kfuncs.bpf.o: $(obj)/test_inlinable_kfuncs.bpf.bc.o
	$(Q)$(LLC) -mcpu=v3 --mtriple=bpf --filetype=obj $< -o $@

$(obj)/test_inlinable_kfuncs.bpf.linked.o: $(obj)/test_inlinable_kfuncs.bpf.o
	$(Q)$(STRIP) --strip-debug --remove-section=.*BTF* -o $@ $<

$(obj)/bpf_testmod_core.o: $(obj)/test_inlinable_kfuncs.bpf.linked.o

endif
