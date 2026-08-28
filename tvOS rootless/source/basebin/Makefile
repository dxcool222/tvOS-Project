THEOS ?= $(HOME)/theos
export THEOS

TARGET := appletv:clang:16.4:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

# Theos cannot build with spaces in $(abspath …); use /tmp symlinks (see scripts/setup_build_symlinks.sh).
$(shell bash "$(abspath ../scripts/setup_build_symlinks.sh)" 2>/dev/null)
ROOT := /tmp/dopamin-root
KFD_ROOT := /tmp/dopamin-kfd
DOPAMINE := /tmp/dopamin-dopamine
CHoma := $(DOPAMINE)/BaseBin/ChOma
XPF_DIR := $(DOPAMINE)/BaseBin/XPF
LIBJB := $(DOPAMINE)/BaseBin/libjailbreak
LITEHOOK := $(DOPAMINE)/BaseBin/_external/modules/litehook/src
OUT := out

XPC_INC :=
LIBARCHIVE := $(shell brew --prefix libarchive 2>/dev/null || echo /opt/homebrew/opt/libarchive)

INC := \
	-I$(OUT)/include \
	-I$(KFD_ROOT)/stubs \
	-I$(DOPAMINE)/BaseBin/_external/include \
	-I$(CHoma)/src \
	-I$(XPF_DIR)/src \
	-I$(LIBJB)/src \
	-I$(LIBJB)/src/atomic_headers \
	-I$(LITEHOOK)

CCFLAGS := $(TARGET_CFLAGS) $(VERSIONFLAGS) -isysroot $(ISYSROOT) \
	-Wno-error -Wno-ambiguous-macro -Wno-unused-variable -Wno-unused-but-set-variable -Wno-availability \
	-D_DARWIN_UNLIMITED_SYSCALLS \
	-fobjc-arc -O2 -Wno-deprecated-declarations $(XPC_INC) $(INC)
LDFLAGS := $(TARGET_LDFLAGS) $(VERSIONFLAGS) -isysroot $(SYSROOT) -lcompression -lbsm

CHOMa_SRCS := $(wildcard $(CHoma)/src/*.c)
XPF_SRCS := $(XPF_DIR)/src/common.c $(XPF_DIR)/src/decompress.c $(XPF_DIR)/src/xpf.c \
            $(XPF_DIR)/src/non_ppl.c $(XPF_DIR)/src/ppl.c $(XPF_DIR)/src/bad_recovery.c
# libjailbreak: phys-rw_pte + translation for build 22 handoff (tvOS pmap util stub)
LIBJB_SRCS := \
	$(LIBJB)/src/info.c \
	$(LIBJB)/src/primitives.c \
	$(LIBJB)/src/translation.c \
	$(LIBJB)/src/kernel.c \
	$(LIBJB)/src/jbserver.c \
	$(LIBJB)/src/jbserver_boomerang.c \
	$(LIBJB)/src/physrw_pte.c \
	$(LIBJB)/src/trustcache.c \
	$(LIBJB)/src/kalloc_pt.m \
	$(KFD_ROOT)/stubs/dt_mach_thread_shim.c \
	$(KFD_ROOT)/stubs/dt_kcall_arm64_tvos.c \
	$(KFD_ROOT)/stubs/dt_kcall_fugu14_minimal.c \
	$(LIBJB)/src/kcall_Fugu14.S \
	$(KFD_ROOT)/stubs/dt_pmap_util.c \
	$(KFD_ROOT)/stubs/dt_pte_kwrite_stub.c

LIBJB_OBJS := \
	$(OUT)/obj/libjb/info.o \
	$(OUT)/obj/libjb/primitives.o \
	$(OUT)/obj/libjb/translation.o \
	$(OUT)/obj/libjb/kernel.o \
	$(OUT)/obj/libjb/jbserver.o \
	$(OUT)/obj/libjb/jbserver_boomerang.o \
	$(OUT)/obj/libjb/physrw_pte.o \
	$(OUT)/obj/libjb/trustcache.o \
	$(OUT)/obj/libjb/kalloc_pt.o \
	$(OUT)/obj/libjb/dt_mach_thread_shim.o \
	$(OUT)/obj/libjb/dt_kcall_arm64_tvos.o \
	$(OUT)/obj/libjb/dt_kcall_fugu14_minimal.o \
	$(OUT)/obj/libjb/kcall_Fugu14_asm.o \
	$(OUT)/obj/libjb/dt_pmap_util.o \
	$(OUT)/obj/libjb/dt_pte_kwrite_stub.o

LIBJB_LDFLAGS := \
	-Wl,-u,_libjailbreak_physrw_pte_init \
	-Wl,-u,_device_supports_physrw_pte \
	-Wl,-export_dynamic

CHOMa_OBJS := $(patsubst $(CHoma)/src/%.c,$(OUT)/obj/choma/%.o,$(CHOMa_SRCS))
XPF_OBJS := $(patsubst $(XPF_DIR)/src/%.c,$(OUT)/obj/xpf/%.o,$(XPF_SRCS))

.PHONY: dylibs clean
dylibs: $(OUT)/libchoma.dylib $(OUT)/libxpf.dylib $(OUT)/libjailbreak.dylib

$(OUT)/obj/choma $(OUT)/obj/xpf $(OUT)/obj/libjb:
	@mkdir -p $@

$(OUT)/include/choma $(OUT)/include/xpf: | $(OUT)/obj/choma
	@mkdir -p $(OUT)/include/choma $(OUT)/include/xpf
	@cp $(CHoma)/src/*.h $(OUT)/include/choma/
	@cp $(XPF_DIR)/src/xpf.h $(OUT)/include/xpf/

$(OUT)/obj/choma/%.o: $(CHoma)/src/%.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -DDISABLE_SIGNING=1 -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/xpf/%.o: $(XPF_DIR)/src/%.c | $(OUT)/include/xpf
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/%.o: $(LIBJB)/src/%.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/kalloc_pt.o: $(LIBJB)/src/kalloc_pt.m | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/kcall_Fugu14_asm.o: $(LIBJB)/src/kcall_Fugu14.S | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/dt_pte_kwrite_stub.o: $(KFD_ROOT)/stubs/dt_pte_kwrite_stub.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/dt_pmap_util.o: $(KFD_ROOT)/stubs/dt_pmap_util.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/dt_mach_thread_shim.o: $(KFD_ROOT)/stubs/dt_mach_thread_shim.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/dt_kcall_arm64_tvos.o: $(KFD_ROOT)/stubs/dt_kcall_arm64_tvos.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/obj/libjb/dt_kcall_fugu14_minimal.o: $(KFD_ROOT)/stubs/dt_kcall_fugu14_minimal.c | $(OUT)/include/choma
	@mkdir -p $(dir $@)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -fPIC -c $< -o $@$(ECHO_END)

$(OUT)/libchoma.dylib: $(CHOMa_OBJS)
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -dynamiclib -install_name @executable_path/Frameworks/libchoma.dylib \
		$^ -o $@ $(CHoma)/external/ios/libcrypto.a -framework CoreFoundation$(ECHO_END)
	$(ECHO_NOTHING)$(TARGET_CODESIGN) $(TARGET_CODESIGN_FLAGS) $@$(ECHO_END)

$(OUT)/libxpf.dylib: $(XPF_OBJS) $(OUT)/libchoma.dylib
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -dynamiclib -install_name @executable_path/Frameworks/libxpf.dylib \
		$(XPF_OBJS) -o $@ $(LDFLAGS) -L$(OUT) -lchoma -framework Foundation$(ECHO_END)
	$(ECHO_NOTHING)$(TARGET_CODESIGN) $(TARGET_CODESIGN_FLAGS) $@$(ECHO_END)

$(OUT)/libjailbreak.dylib: $(LIBJB_OBJS) $(OUT)/libchoma.dylib
	$(ECHO_NOTHING)$(TARGET_CC) $(CCFLAGS) -dynamiclib -install_name @executable_path/Frameworks/libjailbreak.dylib \
		$(LIBJB_OBJS) -o $@ $(LDFLAGS) -L$(OUT) -lchoma $(LIBJB_LDFLAGS) \
		-framework Foundation -framework CoreServices -framework Security$(ECHO_END)
	$(ECHO_NOTHING)$(TARGET_CODESIGN) $(TARGET_CODESIGN_FLAGS) $@$(ECHO_END)

clean:
	@rm -rf $(OUT)
