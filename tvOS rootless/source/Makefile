THEOS ?= $(HOME)/theos
export THEOS

TARGET := appletv:clang:16.4:14.0
ARCHS = arm64
INSTALL_TARGET_PROCESSES = dopamin-tvOS-kfd

include $(THEOS)/makefiles/common.mk

$(shell bash "$(abspath scripts/setup_build_symlinks.sh)" 2>/dev/null)
# Out-of-tree build root via /tmp symlink (Theos/Make cannot handle spaces in abspath).
ROOT := /tmp/dopamin-build/theos-root
$(shell mkdir -p /tmp/dopamin-build/theos-root)
DOPAMINE := /tmp/dopamin-dopamine
KFD := $(DOPAMINE)/Application/Dopamine/Exploits/kfd
BASEBIN := $(THEOS_PROJECT_DIR)/basebin/out
$(shell mkdir -p "$(ROOT)")

APPLICATION_NAME = dopamin-tvOS-kfd

$(APPLICATION_NAME)_FILES = main.m DTKFDConfig.m DTSettingsViewController.m DTLogCapture.m DTRunLogger.m DTDeviceInfo.m DTKernelPath.m DTKFDRunner.m DTBootstrap.m spawn_root.m DTRootHelperClient.m dt_respring.c dt_session_probe.c dt_baked_offsets.m dt_kfund_import.m dt_xpf_patchfind.m dt_misaka_offsets.m dt_physrw.m dt_do_fun.m dt_pte_kwrite_perf.c dt_kcall_planb.m dt_macho_canonical_id.c dt_bootstrap_preflight.m dt_build102739m.m dt_build102739n.m dt_choma_platform_sign.c dt_build710_preboot.m dt_build583_client.m dt_build653_client.m dt_build674_client.m dt_build681_client.m dt_build681_boomerang.m dt_build688a_client.m dt_build690_client.m dt_build691_client.m dt_build692_client.m dt_build694_client.m dt_build696_client.m dt_build697_client.m dt_build698_client.m dt_build699_client.m handoff674/frozen661_embed.c kfd_tvos.m darksword_tvos.m dt_darksword_platform.m dt_darksword_stages.m dt_kernel_exploit.m dt_contiguous_mapping.m dt_exploit_lifecycle.m stubs/syscall_shim.c dt_rootless_state.m dt_rootless_install.m dt_rootless_trust.m dt_rootless_dyld_delivery.m dt_rootless_bringup.m dt_rootless_r6.m dt_rootless_r6_decide.c dt_rootless_r9_product.c dt_rootless_orch.c dt_rootless_path_policy.c dt_rootless_tree_ops.c dt_rootless_tree_ops_r12_legacy.c dt_rootless_platform_device.m
$(APPLICATION_NAME)_CFLAGS = -fobjc-arc -O2 -Wno-deprecated-declarations -Wno-error \
	-D_DARWIN_UNLIMITED_SYSCALLS \
	-DDT_POST_KOPEN_PTE=0 \
	-DDT_PHYSRW_HANDOFF=1 \
					-DDT_BUILD_NUM=102738 \
	$(if $(filter 1,$(DT_102738W_VARIANT)),-DDT_BUILD102738W_VARIANT=1,) \
	$(if $(filter 1,$(DT_102738X_VARIANT)),-DDT_BUILD102738X_VARIANT=1,) \
	$(if $(filter 1,$(DT_102738Y_VARIANT)),-DDT_BUILD102738Y_VARIANT=1,) \
	$(if $(filter 1,$(DT_102738Z_VARIANT)),-DDT_BUILD102738Z_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739A_VARIANT)),-DDT_BUILD102739A_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739B_VARIANT)),-DDT_BUILD102739B_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739C_VARIANT)),-DDT_BUILD102739C_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739D_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739E_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739F_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739G_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739H_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739I_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1,) \
	$(if $(filter 1,$(DT_102739J_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1 -DDT_BUILD102739J_VARIANT=1,) \
		$(if $(filter 1,$(DT_102739K_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1 -DDT_BUILD102739J_VARIANT=1 -DDT_BUILD102739K_VARIANT=1,) \
		$(if $(filter 1,$(DT_102739L_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1 -DDT_BUILD102739J_VARIANT=1 -DDT_BUILD102739K_VARIANT=1 -DDT_BUILD102739L_VARIANT=1,) \
			$(if $(filter 1,$(DT_102739M_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1 -DDT_BUILD102739J_VARIANT=1 -DDT_BUILD102739K_VARIANT=1 -DDT_BUILD102739L_VARIANT=1 -DDT_BUILD102739M_VARIANT=1,) \
			$(if $(filter 1,$(DT_102739N_VARIANT)),-DDT_BUILD102739C_VARIANT=1 -DDT_BUILD102739D_VARIANT=1 -DDT_BUILD102739E_VARIANT=1 -DDT_BUILD102739F_VARIANT=1 -DDT_BUILD102739G_VARIANT=1 -DDT_BUILD102739H_VARIANT=1 -DDT_BUILD102739I_VARIANT=1 -DDT_BUILD102739J_VARIANT=1 -DDT_BUILD102739K_VARIANT=1 -DDT_BUILD102739L_VARIANT=1 -DDT_BUILD102739M_VARIANT=1 -DDT_BUILD102739N_VARIANT=1,) \
    $(if $(filter 1,$(DT_ROOTLESS_R4)),-DDT_ROOTLESS_R4=1,) \
    $(if $(filter 1,$(DT_ROOTLESS_R24)),-DDT_ROOTLESS_R24=1 -DDT_ROOTLESS_R24_CBR=1,) \
	-I"$(THEOS_PROJECT_DIR)/generated" \
	-I"$(THEOS_PROJECT_DIR)/handoff674" \
	-I"$(THEOS_PROJECT_DIR)/stubs" \
	-I"$(THEOS_PROJECT_DIR)/libkfd" \
	-I"$(THEOS)/sdks/AppleTVOS16.4.sdk/System/Library/Frameworks/IOKit.framework/Versions/A/Headers" \
	-I"$(DOPAMINE)/BaseBin/_external/include" \
	-I"$(BASEBIN)/include" \
	-I"$(BASEBIN)/include/choma" \
	-I"$(BASEBIN)/include/xpf" \
	-I"$(KFD)/Exploit" \
	-I"$(KFD)" \
	-I"$(THEOS_PROJECT_DIR)/build/rootless_r4/include/libjailbreak" \
	-I"$(THEOS_PROJECT_DIR)/handoff516/source/libjailbreak/core" \
	-I"$(THEOS_PROJECT_DIR)/handoff516/source/include/libjailbreak" \
	-I"$(DOPAMINE)/BaseBin/libjailbreak/src"
$(APPLICATION_NAME)_FRAMEWORKS = UIKit Foundation IOKit IOSurface
$(APPLICATION_NAME)_LDFLAGS = -L"$(BASEBIN)" -lxpf -ljailbreak -lchoma -lcompression \
	-Wl,-rpath,@executable_path/Frameworks \
	-Wl,-reproducible \
		$(if $(filter 1,$(DT_102739M_VARIANT)),-Xlinker -sectcreate -Xlinker __DATA -Xlinker __dtmhelper -Xlinker $(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m,) \
		$(if $(filter 1,$(DT_102739N_VARIANT)),-Xlinker -sectcreate -Xlinker __DATA -Xlinker __dtmhelper -Xlinker $(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m -Xlinker -sectcreate -Xlinker __DATA -Xlinker __dtnhelper -Xlinker $(THEOS_PROJECT_DIR)/.theos/obj/build102739n/dt_probe102739n,)
$(APPLICATION_NAME)_INFOPLIST = Info.plist
$(APPLICATION_NAME)_CODESIGN_FLAGS = -S"$(THEOS_PROJECT_DIR)/entitlements.plist"

before-all::
	@DT_NUM=$$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$(THEOS_PROJECT_DIR)/Makefile" | head -1 | cut -d= -f2); \
	if [ "$(DT_SKIP_BASEBIN_REBUILD)" = "1" ]; then \
		echo "=== basebin dylibs: explicit skip ==="; \
	elif [ ! -f "$(THEOS_PROJECT_DIR)/basebin/out/libjailbreak.dylib" ] || [ "$(DT_REPRO_BUILD)" = "1" ]; then \
		$(MAKE) -C basebin dylibs; \
	elif [ "$$DT_NUM" = "102733" ] || [ "$$DT_NUM" = "102734" ] || [ "$$DT_NUM" = "102735" ] || [ "$$DT_NUM" = "102736" ] || [ "$$DT_NUM" = "102737" ] || [ "$$DT_NUM" = "102738" ]; then \
		echo "=== basebin dylibs: reuse existing outputs ==="; \
	else \
		$(MAKE) -C basebin dylibs; \
	fi
	@if [ "$(DT_ROOTLESS_R24)" = "1" ]; then \
		if [ "$(DT_REPRO_BUILD)" = "1" ]; then \
			echo "=== REPRO R24: seed frozen Handoff516 trio from source ==="; \
			bash "$(THEOS_PROJECT_DIR)/scripts/bootstrap_r24_seed.sh"; \
		fi; \
		if [ "$(DT_R24_DYLD_PREBUILT)" = "1" ]; then \
			test -f "$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/dyld.frozen"; \
			test -f "$(THEOS_PROJECT_DIR)/generated/dt_rootless_r24_dyld_identity.h"; \
			echo "=== ROOTLESS R24 H16: use upstream-frozen dyld + generated identity ==="; \
		else \
			echo "=== ROOTLESS R24 H16: exact tvOS dyld delivery artifact ==="; \
			bash "$(THEOS_PROJECT_DIR)/scripts/build_r24_dyld_delivery.sh"; \
		fi; \
		echo "=== ROOTLESS R24: rebuild current launchd/systemhook delivery pair ==="; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build_rootless_r4_handoff516.sh"; \
		echo "=== ROOTLESS R24 D0: generate MAIN expect pins from Handoff516 ==="; \
		bash "$(THEOS_PROJECT_DIR)/scripts/generate_rootless_r24_d0_expect.sh"; \
	fi
	@DT_NUM=$$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$(THEOS_PROJECT_DIR)/Makefile" | head -1 | cut -d= -f2); \
	if [ "$$DT_NUM" = "102733" ]; then \
		echo "=== auxiliary handoff/helper outputs frozen: reuse existing outputs ==="; \
	elif [ "$$DT_NUM" = "102734" ]; then \
		echo "=== BUILD102734C helper-only rebuild: frozen trio preserved ==="; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build102734c_opainject_helper.sh"; \
		elif [ "$$DT_NUM" = "102735" ]; then \
			echo "=== BUILD102735D hook-only trace rebuild: frozen helper/libs preserved ==="; \
			bash "$(THEOS_PROJECT_DIR)/scripts/build102735d_trace_hook.sh"; \
		elif [ "$$DT_NUM" = "102736" ]; then \
			echo "=== BUILD102736C helper-only task-port repair: BUILD102735D hook/libs preserved ==="; \
			bash "$(THEOS_PROJECT_DIR)/scripts/build102736c_opainject_helper.sh"; \
		elif [ "$$DT_NUM" = "102737" ]; then \
			echo "=== BUILD102737D PTE handoff + Wall2 lifetime diagnostic: isolated telemetry outputs ==="; \
			bash "$(THEOS_PROJECT_DIR)/scripts/build102737d_pte_handoff_diag.sh"; \
		elif [ "$$DT_NUM" = "102738" ]; then \
			if [ "$(DT_ROOTLESS_R24)" = "1" ] && [ "$(DT_REPRO_BUILD)" = "1" ]; then \
				echo "=== REPRO BUILD102738R: build auxiliary handoffs + bootstrap_g2 from source ==="; \
				bash "$(THEOS_PROJECT_DIR)/scripts/pack_tools_ldid.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/pack_bootstrap_g2.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build_bootstraphelper.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build583_handoff.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build653_handoff.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build672_handoff.sh"; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build674_control661_embed.sh"; \
			elif [ "$(DT_ROOTLESS_R24)" = "1" ] || [ "$(DT_102738_PREBUILT)" = "1" ] || [ "$(DT_102738W_PREBUILT)" = "1" ]; then \
				echo "=== BUILD102738 variant prebuilt hook: frozen BUILD102738R chain ==="; \
			else \
				echo "=== BUILD102738P launchd GOT protection-only probe: frozen BUILD102737D chain ==="; \
				bash "$(THEOS_PROJECT_DIR)/scripts/build102738p_got_protection_probe.sh"; \
			fi; \
	else \
		bash "$(THEOS_PROJECT_DIR)/scripts/pack_bootstrap_g2.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/pack_tools_ldid.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build_bootstraphelper.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build583_handoff.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build653_handoff.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build672_handoff.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build674_control661_embed.sh"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/build681_handoff.sh"; \
	fi

.PHONY: basebin ipa
basebin:
	@$(MAKE) -C basebin dylibs

DEBUG_APP := $(THEOS_PROJECT_DIR)/.theos/obj/appletv/debug/$(APPLICATION_NAME).app
ENTITLEMENTS := $(THEOS_PROJECT_DIR)/entitlements.plist

fixup-dylibs::
	@mkdir -p "$(DEBUG_APP)/Frameworks"
	@if [ "$(DT_ROOTLESS_R24)" = "1" ]; then \
		rm -rf "$(DEBUG_APP)/R24DyldDelivery"; \
		mkdir -p "$(DEBUG_APP)/R24DyldDelivery"; \
		test -f "$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/dyld.frozen"; \
		cp "$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/dyld.frozen" "$(DEBUG_APP)/R24DyldDelivery/dyld"; \
		cmp -s "$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/dyld.frozen" "$(DEBUG_APP)/R24DyldDelivery/dyld"; \
		cp "$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/R24_TVOS_DYLD_DELIVERY_IDENTITY.json" "$(DEBUG_APP)/R24DyldDelivery/"; \
		chmod 0755 "$(DEBUG_APP)/R24DyldDelivery/dyld"; \
	fi
	@cp "$(BASEBIN)/libchoma.dylib" "$(BASEBIN)/libxpf.dylib" "$(BASEBIN)/libjailbreak.dylib" \
		"$(DEBUG_APP)/Frameworks/"
	@rm -rf "$(DEBUG_APP)/bootstrap_g2"
	@cp -R "$(THEOS_PROJECT_DIR)/bootstrap_g2" "$(DEBUG_APP)/bootstrap_g2"
	@rm -rf "$(DEBUG_APP)/Tools"
	@mkdir -p "$(DEBUG_APP)/Tools"
	@cp "$(THEOS_PROJECT_DIR)/Tools/ldid" "$(DEBUG_APP)/Tools/ldid"
	@cp "$(THEOS_PROJECT_DIR)/Tools/entitlements_tools.plist" "$(DEBUG_APP)/Tools/entitlements_tools.plist"
	@chmod +x "$(DEBUG_APP)/Tools/ldid"
	@$(TARGET_CODESIGN) -S"$(THEOS_PROJECT_DIR)/Tools/entitlements_tools.plist" "$(DEBUG_APP)/Tools/ldid"
	@cp "$(THEOS_PROJECT_DIR)/Info.plist" "$(DEBUG_APP)/Info.plist"
			@if [ "$(DT_102739K_VARIANT)" = "1" ] || [ "$(DT_102739L_VARIANT)" = "1" ] || [ "$(DT_102739M_VARIANT)" = "1" ] || [ "$(DT_102739N_VARIANT)" = "1" ]; then \
			test -f "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739K_CF1900_PATHS.tsv"; \
			cp "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739K_CF1900_PATHS.tsv" "$(DEBUG_APP)/"; \
		fi
		@if [ "$(DT_102739L_VARIANT)" = "1" ] || [ "$(DT_102739M_VARIANT)" = "1" ] || [ "$(DT_102739N_VARIANT)" = "1" ]; then \
			test -f "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739L_ADAPTED_PLAN.tsv"; \
			test -f "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739L_POLICY.tsv"; \
			cp "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739L_ADAPTED_PLAN.tsv" "$(DEBUG_APP)/"; \
			cp "$(THEOS_PROJECT_DIR)/bootstrap_preflight/BUILD102739L_POLICY.tsv" "$(DEBUG_APP)/"; \
		fi
	@if [ "$(DT_102739M_VARIANT)" = "1" ]; then \
		test -f "$(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m"; \
		cp "$(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m" "$(DEBUG_APP)/dt_probe102739m"; \
		chmod 0755 "$(DEBUG_APP)/dt_probe102739m"; \
	fi
	@if [ "$(DT_102739N_VARIANT)" = "1" ]; then \
		test -f "$(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m"; \
		test -f "$(THEOS_PROJECT_DIR)/.theos/obj/build102739n/dt_probe102739n"; \
		cp "$(THEOS_PROJECT_DIR)/.theos/obj/build102739m/dt_probe102739m" "$(DEBUG_APP)/dt_probe102739m"; \
		cp "$(THEOS_PROJECT_DIR)/.theos/obj/build102739n/dt_probe102739n" "$(DEBUG_APP)/dt_probe102739n"; \
		chmod 0755 "$(DEBUG_APP)/dt_probe102739m" "$(DEBUG_APP)/dt_probe102739n"; \
	fi
	@cp "$(THEOS_PROJECT_DIR)/entitlements_helper.plist" "$(DEBUG_APP)/entitlements_helper.plist"
	@cp "$(THEOS_PROJECT_DIR)/entitlements_probe583_helper.plist" "$(DEBUG_APP)/entitlements_probe583_helper.plist"
	@cp "$(THEOS_PROJECT_DIR)/entitlements_direct653_helper.plist" "$(DEBUG_APP)/entitlements_direct653_helper.plist"
	@cp "$(THEOS_PROJECT_DIR)/entitlements_direct672_tool.plist" "$(DEBUG_APP)/entitlements_direct672_tool.plist"
	@mkdir -p "$(DEBUG_APP)/Handoff674/Control661"
	@cp "$(THEOS_PROJECT_DIR)/.theos/obj/handoff674/Control661/dt_direct653_helper_control661" "$(DEBUG_APP)/Handoff674/Control661/"
	@chmod +x "$(DEBUG_APP)/Handoff674/Control661/dt_direct653_helper_control661"
	@mkdir -p "$(DEBUG_APP)/Handoff653"
	@cp "$(THEOS_PROJECT_DIR)/.theos/obj/handoff653/Handoff653/dt_direct653_helper" "$(DEBUG_APP)/Handoff653/"
	@chmod +x "$(DEBUG_APP)/Handoff653/dt_direct653_helper"
	@mkdir -p "$(DEBUG_APP)/Handoff672"
	@cp "$(THEOS_PROJECT_DIR)/.theos/obj/handoff672/Handoff672/dt_tool672_probe" "$(DEBUG_APP)/Handoff672/"
	@chmod +x "$(DEBUG_APP)/Handoff672/dt_tool672_probe"
	@mkdir -p "$(DEBUG_APP)/Handoff583"
	@cp "$(THEOS_PROJECT_DIR)/.theos/obj/handoff583/Handoff583/dt_probe583_helper" "$(DEBUG_APP)/Handoff583/"
	@chmod +x "$(DEBUG_APP)/Handoff583/dt_probe583_helper"
	@rm -rf "$(DEBUG_APP)/Handoff516"
	@mkdir -p "$(DEBUG_APP)/Handoff516"
	@if [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		echo "=== ROOTLESS-R5: pack fuller Handoff516 from build/rootless_r4 ==="; \
		test -f "$(THEOS_PROJECT_DIR)/build/rootless_r4/Handoff516/launchdhook516.dylib"; \
		cp -R "$(THEOS_PROJECT_DIR)/build/rootless_r4/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
		if [ -f "$(THEOS_PROJECT_DIR)/build/rootless_r4/Frameworks/libjailbreak.dylib" ]; then \
			cp "$(THEOS_PROJECT_DIR)/build/rootless_r4/Frameworks/libjailbreak.dylib" "$(DEBUG_APP)/Frameworks/libjailbreak.dylib"; \
			install_name_tool -change "@loader_path/libchoma.dylib" "@executable_path/Frameworks/libchoma.dylib" \
				"$(DEBUG_APP)/Frameworks/libjailbreak.dylib" 2>/dev/null || true; \
		fi; \
	else \
	DT_NUM=$$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$(THEOS_PROJECT_DIR)/Makefile" | head -1 | cut -d= -f2); \
		if [ "$$DT_NUM" = "102735" ]; then \
			cp -R "$(THEOS_PROJECT_DIR)/build/102735D/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
		elif [ "$$DT_NUM" = "102736" ]; then \
			cp -R "$(THEOS_PROJECT_DIR)/build/102736C/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
		elif [ "$$DT_NUM" = "102737" ]; then \
			cp -R "$(THEOS_PROJECT_DIR)/build/102737D/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
		elif [ "$$DT_NUM" = "102738" ]; then \
			cp -R "$(THEOS_PROJECT_DIR)/build/102738P/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
	elif [ "$$DT_NUM" = "102733" ] || [ "$$DT_NUM" = "102734" ]; then \
		cp -R "$(THEOS_PROJECT_DIR)/build/102732C/Payload/dopamin-tvOS-kfd.app/Handoff516/." "$(DEBUG_APP)/Handoff516/"; \
		if [ "$$DT_NUM" = "102734" ]; then \
			cp "$(THEOS_PROJECT_DIR)/.theos/obj/handoff681/Handoff516/dt_opainject516" "$(DEBUG_APP)/Handoff516/dt_opainject516"; \
			chmod +x "$(DEBUG_APP)/Handoff516/dt_opainject516"; \
			{ \
				echo "CFBundleVersion=102734"; \
				echo "launchdhook516.dylib=8446a2386197a7fd0a13e7701843f7c29d8682b4d6fd759909be25c87bf7f0e4"; \
				echo "libjailbreak.dylib=9faa26a8ddd6c79ea004c61cdbd8f75c0acf3f2a6b9092fe082f08349cadad79"; \
				echo "libchoma.dylib=40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"; \
			} > "$(DEBUG_APP)/Handoff516/BUILD102734C_RESOURCE_MANIFEST.txt"; \
		fi; \
	else \
		for f in "$(THEOS_PROJECT_DIR)/.theos/obj/handoff681/Handoff516/"*; do \
			case "$$f" in *.i64) continue ;; esac; \
			cp "$$f" "$(DEBUG_APP)/Handoff516/"; \
		done; \
		chmod +x "$(DEBUG_APP)/Handoff516/"* 2>/dev/null || true; \
		for f in libjailbreak libchoma; do \
			$(TARGET_CODESIGN) -S "$(DEBUG_APP)/Handoff516/$$f.dylib"; \
		done; \
		cp "$(THEOS_PROJECT_DIR)/handoff681/entitlements_launchdhook681.plist" "$(DEBUG_APP)/Handoff516/"; \
		bash "$(THEOS_PROJECT_DIR)/scripts/write_hook_build_manifest.sh" \
			"$(DEBUG_APP)/Handoff516/launchdhook516.dylib" \
			"$(DEBUG_APP)/Handoff516/hook_build_manifest.txt"; \
	fi; \
	fi
	@chmod +x "$(DEBUG_APP)/Handoff516/"* 2>/dev/null || true
	@cp "$(THEOS_PROJECT_DIR)/.theos/obj/bootstraphelper/bootstraphelper" "$(DEBUG_APP)/bootstraphelper"
	@chmod +x "$(DEBUG_APP)/bootstraphelper"
	@$(TARGET_CODESIGN) -S"$(THEOS_PROJECT_DIR)/entitlements_helper.plist" "$(DEBUG_APP)/bootstraphelper"
	@install_name_tool -change "@loader_path/libjailbreak.dylib" "@executable_path/Frameworks/libjailbreak.dylib" \
		"$(DEBUG_APP)/$(APPLICATION_NAME)" 2>/dev/null || true
	@install_name_tool -change "@loader_path/libxpf.dylib" "@executable_path/Frameworks/libxpf.dylib" \
		"$(DEBUG_APP)/$(APPLICATION_NAME)" 2>/dev/null || true
	@install_name_tool -change "@loader_path/libchoma.dylib" "@executable_path/Frameworks/libchoma.dylib" \
		"$(DEBUG_APP)/$(APPLICATION_NAME)" 2>/dev/null || true
	@install_name_tool -id "@executable_path/Frameworks/libchoma.dylib" \
		"$(DEBUG_APP)/Frameworks/libchoma.dylib" 2>/dev/null || true
	@install_name_tool -id "@executable_path/Frameworks/libjailbreak.dylib" \
		"$(DEBUG_APP)/Frameworks/libjailbreak.dylib" 2>/dev/null || true
	@install_name_tool -change "@loader_path/libchoma.dylib" "@executable_path/Frameworks/libchoma.dylib" \
		"$(DEBUG_APP)/Frameworks/libjailbreak.dylib" 2>/dev/null || true
	@DT_NUM=$$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$(THEOS_PROJECT_DIR)/Makefile" | head -1 | cut -d= -f2); \
	if [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		echo "=== ROOTLESS: keep Frameworks/libjailbreak from build/rootless_r4 ==="; \
	elif [ "$$DT_NUM" = "102737" ] || [ "$$DT_NUM" = "102738" ]; then \
		if [ "$$DT_NUM" = "102738" ]; then FW_SOURCE="$(THEOS_PROJECT_DIR)/build/102738P/Frameworks/libjailbreak.dylib"; else FW_SOURCE="$(THEOS_PROJECT_DIR)/build/102737D/Frameworks/libjailbreak.dylib"; fi; \
		cp "$$FW_SOURCE" "$(DEBUG_APP)/Frameworks/libjailbreak.dylib"; \
		install_name_tool -change "@loader_path/libchoma.dylib" "@executable_path/Frameworks/libchoma.dylib" \
			"$(DEBUG_APP)/Frameworks/libjailbreak.dylib" 2>/dev/null || true; \
	fi
	@for f in libchoma libxpf libjailbreak; do \
		$(TARGET_CODESIGN) -S "$(DEBUG_APP)/Frameworks/$$f.dylib"; \
	done
	@if [ "$(DT_ROOTLESS_R24)" = "1" ]; then \
		bash "$(THEOS_PROJECT_DIR)/scripts/verify_r24_dyld_packaging_identity.sh" \
			"$(DEBUG_APP)" \
			"$(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/R24_DYLD_IDENTITY_STAMP.txt"; \
	fi
	@if [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		: "$${DT_BUILD_ROOT:?DT_BUILD_ROOT required for ROOTLESS-R4 pack}"; \
		: "$${DT_TOOLS_ROOT:?DT_TOOLS_ROOT required for ROOTLESS-R4 pack}"; \
		echo "=== ROOTLESS-R4 payload + trust + path manifest ==="; \
		test -f "$$DT_BUILD_ROOT/artifacts/ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"; \
		cp "$$DT_BUILD_ROOT/artifacts/ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv" "$(DEBUG_APP)/"; \
		rm -rf "$(DEBUG_APP)/RootlessPayload"; \
		mkdir -p "$(DEBUG_APP)/RootlessPayload"; \
		rsync -a --delete "$$DT_BUILD_ROOT/work/jbroot_transformed/" "$(DEBUG_APP)/RootlessPayload/"; \
		python3 "$$DT_TOOLS_ROOT/rootless_add_dest_libiosexec_rpath.py" \
			"$(DEBUG_APP)/RootlessPayload" \
			--verify-only; \
		python3 "$$DT_TOOLS_ROOT/rootless_sign_uialert_cfusernotification.py" \
			"$(DEBUG_APP)/RootlessPayload" \
			--trust "$(DEBUG_APP)/ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv" \
			--verify-only; \
        python3 "$$DT_TOOLS_ROOT/rootless_payload_path_manifest.py" \
			"$(DEBUG_APP)/RootlessPayload" \
			-o "$(DEBUG_APP)/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"; \
		python3 "$$DT_TOOLS_ROOT/rootless_force_setuid_manifest.py" \
			"$(DEBUG_APP)/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"; \
		python3 "$$DT_TOOLS_ROOT/rootless_encode_abs_packed_symlinks.py" \
			"$(DEBUG_APP)/RootlessPayload" \
			"$(DEBUG_APP)/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"; \
		python3 "$$DT_TOOLS_ROOT/rootless_encode_packed_machos.py" \
			"$(DEBUG_APP)/RootlessPayload" \
			"$(DEBUG_APP)/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"; \
		cp "$(DEBUG_APP)/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv" \
			"$$DT_BUILD_ROOT/artifacts/ROOTLESS_R4_PAYLOAD_PATH_MANIFEST.tsv"; \
		HOOK_SHA=$$(shasum -a 256 "$(DEBUG_APP)/Handoff516/launchdhook516.dylib" | awk '{print $$1}'); \
		{ \
			echo "ROOTLESS_VARIANT=R6"; \
			echo "ROOTLESS_ARCH=appletvos-arm64-rootless"; \
			echo "ROOTLESS_PAYLOAD_SCHEMA=R6_PATH_MANIFEST_V1"; \
			echo "ROOTLESS_SCOPE=FULL_TREE_INSTALL_PLUS_FULLER_HANDOFF516"; \
			echo "COMPILED_ROOTLESS_MARKER=ROOTLESS_R6_BEGIN"; \
			echo "FROZEN_BASELINE_DT_BUILD_NUM=102738"; \
			echo "FROZEN_COMPAT_SCOPE=LAUNCHD_GOT_PROTECTION_ONLY"; \
			echo "ROOTLESS_HOOK_SHA256=$$HOOK_SHA"; \
		} > "$(DEBUG_APP)/ROOTLESS_VARIANT_IDENTITY.txt"; \
	fi
	@$(TARGET_CODESIGN) -S"$(ENTITLEMENTS)" "$(DEBUG_APP)/$(APPLICATION_NAME)"

ipa:: all fixup-dylibs
	@mkdir -p "$(THEOS_PROJECT_DIR)/docs/reports"; \
	PAYLOAD="$(THEOS_PROJECT_DIR)/layout/Payload"; \
	DT_NUM=$$(rg -o 'DT_BUILD_NUM=([0-9]+)' "$(THEOS_PROJECT_DIR)/Makefile" | head -1 | cut -d= -f2); \
	case "$$DT_NUM" in \
		102725) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102725R-READONLY-LAUNCHD-GOT-PROBE.ipa" ;; \
		102726) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102726D-LAUNCHD-READ-PATH-DIAGNOSTIC.ipa" ;; \
		102727) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102727R-LAUNCHD-CONTRACT-TELEMETRY.ipa" ;; \
			102728) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102728R-READONLY-LAUNCHD-GOT-CLOSURE.ipa" ;; \
			102729) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102729A-SELF-PAGE-PROTECTION-CONTROL.ipa" ;; \
			102732) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102732C-CONSTRUCTOR-BOOMERANG-ONLY.ipa" ;; \
			102733) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102733C-CONSTRUCTOR-VALIDATOR-FIX.ipa" ;; \
			102734) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102734C-OPAINJECT-TASKPORT-FIX.ipa" ;; \
				102735) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102735D-PREBOOT-CONSTRUCTOR-TRACE.ipa" ;; \
				102736) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102736C-TASKPORT-REPAIR.ipa" ;; \
				102737) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102737D-PTE-HANDOFF-DIAGNOSTIC.ipa" ;; \
				102738) \
					if [ "$(DT_ROOTLESS_R24)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
						NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"; \
					elif [ "$(DT_ROOTLESS_R23)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
						NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-ROOTLESS-R23.ipa"; \
					elif [ "$(DT_ROOTLESS_R22)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
						NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-ROOTLESS-R22.ipa"; \
					elif [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
						NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-ROOTLESS-R21.ipa"; \
					else \
						NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-102738P-LAUNCHD-GOT-PROTECTION-ONLY.ipa"; \
					fi ;; \
			*) NAMED_IPA="$(ROOT)/dopamin-tvOS-kfd-$$DT_NUM.ipa" ;; \
		esac; \
	export DT_ROOTLESS_R4="$(DT_ROOTLESS_R4)"; \
	rm -rf "$$PAYLOAD"; \
	mkdir -p "$$PAYLOAD"; \
	rsync -a "$(DEBUG_APP)/" "$$PAYLOAD/$$(basename "$(DEBUG_APP)")/"; \
	find "$$PAYLOAD" -name '*.i64' -delete; \
	rm -f "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$NAMED_IPA"; \
	cd "$(THEOS_PROJECT_DIR)/layout" && zip -qry "$(ROOT)/dopamin-tvOS-kfd.ipa" Payload; \
	cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$NAMED_IPA"; \
	cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$(THEOS_PROJECT_DIR)/dopamin-tvOS-kfd.ipa"; \
	cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$(THEOS_PROJECT_DIR)/$$(basename "$$NAMED_IPA")"; \
	if [ "$(DT_ROOTLESS_R24)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$DT_BUILD_ROOT/dopamin-tvOS-kfd-ROOTLESS-R24.ipa"; \
	elif [ "$(DT_ROOTLESS_R23)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$DT_BUILD_ROOT/dopamin-tvOS-kfd-ROOTLESS-R23.ipa"; \
	elif [ "$(DT_ROOTLESS_R22)" = "1" ] && [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$DT_BUILD_ROOT/dopamin-tvOS-kfd-ROOTLESS-R22.ipa"; \
	elif [ "$(DT_ROOTLESS_R4)" = "1" ]; then \
		cp "$(ROOT)/dopamin-tvOS-kfd.ipa" "$$DT_BUILD_ROOT/dopamin-tvOS-kfd-ROOTLESS-R21.ipa"; \
	fi; \
	if [ "$$DT_NUM" = "102734" ]; then \
		rm -rf "$(THEOS_PROJECT_DIR)/build/102734C"; \
		mkdir -p "$(THEOS_PROJECT_DIR)/build/102734C"; \
		cp -R "$$PAYLOAD" "$(THEOS_PROJECT_DIR)/build/102734C/"; \
		cp "$$NAMED_IPA" "$(THEOS_PROJECT_DIR)/build/102734C/$$(basename "$$NAMED_IPA")"; \
		elif [ "$$DT_NUM" = "102735" ]; then \
			mkdir -p "$(THEOS_PROJECT_DIR)/build/102735D"; \
			rm -rf "$(THEOS_PROJECT_DIR)/build/102735D/Payload"; \
			cp -R "$$PAYLOAD" "$(THEOS_PROJECT_DIR)/build/102735D/"; \
			cp "$$NAMED_IPA" "$(THEOS_PROJECT_DIR)/build/102735D/$$(basename "$$NAMED_IPA")"; \
		elif [ "$$DT_NUM" = "102736" ]; then \
			mkdir -p "$(THEOS_PROJECT_DIR)/build/102736C"; \
			rm -rf "$(THEOS_PROJECT_DIR)/build/102736C/Payload"; \
			cp -R "$$PAYLOAD" "$(THEOS_PROJECT_DIR)/build/102736C/"; \
			cp "$$NAMED_IPA" "$(THEOS_PROJECT_DIR)/build/102736C/$$(basename "$$NAMED_IPA")"; \
		elif [ "$$DT_NUM" = "102737" ]; then \
			mkdir -p "$(THEOS_PROJECT_DIR)/build/102737D"; \
			rm -rf "$(THEOS_PROJECT_DIR)/build/102737D/Payload"; \
			cp -R "$$PAYLOAD" "$(THEOS_PROJECT_DIR)/build/102737D/"; \
			cp "$$NAMED_IPA" "$(THEOS_PROJECT_DIR)/build/102737D/$$(basename "$$NAMED_IPA")"; \
		elif [ "$$DT_NUM" = "102738" ]; then \
			mkdir -p "$(THEOS_PROJECT_DIR)/build/102738P"; \
			rm -rf "$(THEOS_PROJECT_DIR)/build/102738P/Payload"; \
			cp -R "$$PAYLOAD" "$(THEOS_PROJECT_DIR)/build/102738P/"; \
			cp "$$NAMED_IPA" "$(THEOS_PROJECT_DIR)/build/102738P/$$(basename "$$NAMED_IPA")"; \
		fi; \
	bash "$(THEOS_PROJECT_DIR)/scripts/verify674_ipa_control661.sh" "$(ROOT)/dopamin-tvOS-kfd.ipa"; \
	set -o pipefail; bash "$(THEOS_PROJECT_DIR)/scripts/verify_build_artifact_identity.sh" "$$NAMED_IPA" | tee "$(THEOS_PROJECT_DIR)/docs/reports/BUILD_ARTIFACT_IDENTITY_$$DT_NUM.txt"; \
	echo "IPA: $$NAMED_IPA"; \
	echo "IPA: $(THEOS_PROJECT_DIR)/$$(basename "$$NAMED_IPA")"; \
	echo "IPA: $(ROOT)/dopamin-tvOS-kfd.ipa"

ifeq ($(DT_ROOTLESS_R24),1)
R24_DYLD_IDENTITY_HEADER := $(THEOS_PROJECT_DIR)/generated/dt_rootless_r24_dyld_identity.h
R24_DYLD_IDENTITY_STAMP := $(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/R24_DYLD_IDENTITY_STAMP.txt
R24_DYLD_FROZEN := $(THEOS_PROJECT_DIR)/build/r24_dyld_delivery/dyld.frozen

# Hard dependency: app objects embedding generated identity must rebuild when header/stamp/frozen dyld change.
$(THEOS_OBJ_DIR)/arm64/dt_rootless_dyld_delivery.m.%: $(R24_DYLD_IDENTITY_HEADER) $(R24_DYLD_IDENTITY_STAMP) $(R24_DYLD_FROZEN)
endif

include $(THEOS_MAKE_PATH)/application.mk
