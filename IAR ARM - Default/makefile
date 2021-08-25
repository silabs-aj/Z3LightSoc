################################################################################
# Automatically-generated file. Do not edit!
################################################################################

export WINEDEBUG=-all

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include zll-utility-server/subdir.mk
-include zll-scenes-server/subdir.mk
-include zll-on-off-server/subdir.mk
-include zll-level-control-server/subdir.mk
-include zll-identify-server/subdir.mk
-include zll-commissioning-server/subdir.mk
-include zll-commissioning-common/subdir.mk
-include zcl-framework-core/subdir.mk
-include update-tc-link-key/subdir.mk
-include strong-random/subdir.mk
-include simple-main/subdir.mk
-include serial/EFR32/subdir.mk
-include serial/subdir.mk
-include scenes/subdir.mk
-include scan-dispatch/subdir.mk
-include reporting/subdir.mk
-include on-off/subdir.mk
-include nvm3/EFR32/subdir.mk
-include nvm3/subdir.mk
-include network-steering/subdir.mk
-include network-creator-security/subdir.mk
-include network-creator/subdir.mk
-include mbedtls/EFR32/subdir.mk
-include level-control/subdir.mk
-include interpan/subdir.mk
-include identify/subdir.mk
-include heartbeat/subdir.mk
-include hal-library/EFR32/subdir.mk
-include groups-server/subdir.mk
-include green-power-common/subdir.mk
-include green-power-client/subdir.mk
-include find-and-bind-target/subdir.mk
-include external-generated-files/subdir.mk
-include emlib/subdir.mk
-include emdrv/subdir.mk
-include ember-minimal-printf/subdir.mk
-include efr32/subdir.mk
-include debug-jtag/EFR32/subdir.mk
-include debug-basic-library/EFR32/subdir.mk
-include counters/subdir.mk
-include color-control-server/subdir.mk
-include coexistence-stub/EFR32/subdir.mk
-include ccm-encryption/subdir.mk
-include basic/subdir.mk
-include antenna-stub/subdir.mk
-include aes-cmac/subdir.mk
-include adc/EFR32/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(ASM_UPPER_DEPS)),)
-include $(ASM_UPPER_DEPS)
endif
ifneq ($(strip $(MSA_UPPER_DEPS)),)
-include $(MSA_UPPER_DEPS)
endif
ifneq ($(strip $(ASM_DEPS)),)
-include $(ASM_DEPS)
endif
ifneq ($(strip $(S79_DEPS)),)
-include $(S79_DEPS)
endif
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(MSA_DEPS)),)
-include $(MSA_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(S79_UPPER_DEPS)),)
-include $(S79_UPPER_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: pre-build main-build

# Main-build Target
main-build: Z3LightSoc.out

# Tool invocations
Z3LightSoc.out: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: IAR Linker for ARM'
	ilinkarm $(OBJS) $(USER_OBJS) -o "Z3LightSoc.out" --config "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//platform/base/hal/micro/cortexm3/efm32/iar-cfg.icf" --config_def APP_GECKO_INFO_PAGE_BTL=1 --config_def FLASH_SIZE=524288 --config_def RAM_SIZE=65536 --config_def SIMEEPROM_SIZE=36864 --config_def LOCKBITS_IN_MAINFLASH_SIZE=0 --config_def EMBER_MALLOC_HEAP_SIZE=0 --config_def HEADER_SIZE=256 --config_def PSSTORE_SIZE=0 --config_def LONGTOKEN_SIZE=0 --config_def BTL_SIZE=16384 --no_wrap_diagnostics "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/security-library-link-keys-stub-cortexm3-iar-efr32mg13p-rail/security-library-link-keys-stub.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//platform/emdrv/nvm3/lib/libnvm3_CM4_iar.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/sim-eeprom2-to-nvm3-upgrade-stub-library-cortexm3-iar-efr32mg13p-rail/sim-eeprom2-to-nvm3-upgrade-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-283k1-stub-library-cortexm3-iar-efr32mg13p-rail/cbke-283k1-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/end-device-bind-stub-library-cortexm3-iar-efr32mg13p-rail/end-device-bind-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/zigbee-r22-support-stub-library-cortexm3-iar-efr32mg13p-rail/zigbee-r22-support-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-stub-library-cortexm3-iar-efr32mg13p-rail/cbke-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/multi-network-stub-library-cortexm3-iar-efr32mg13p-rail/multi-network-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/debug-basic-library-cortexm3-iar-efr32mg13p-rail/debug-basic-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/gp-library-cortexm3-iar-efr32mg13p-rail/gp-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-163k1-stub-library-cortexm3-iar-efr32mg13p-rail/cbke-163k1-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//platform/radio/rail_lib/autogen/librail_release/librail_efr32xg13_iar_release.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/binding-table-library-cortexm3-iar-efr32mg13p-rail/binding-table-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/packet-validate-stub-library-cortexm3-iar-efr32mg13p-rail/packet-validate-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/hal-library-cortexm3-iar-efr32mg13p-rail/hal-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/zll-library-cortexm3-iar-efr32mg13p-rail/zll-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/source-route-library-cortexm3-iar-efr32mg13p-rail/source-route-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/zigbee-pro-stack-cortexm3-iar-efr32mg13p-rail/zigbee-pro-stack.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/install-code-library-cortexm3-iar-efr32mg13p-rail/install-code-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/debug-extended-stub-library-cortexm3-iar-efr32mg13p-rail/debug-extended-stub-library.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-library-dsa-verify-stub-cortexm3-iar-efr32mg13p-rail/cbke-library-dsa-verify-stub.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-library-dsa-sign-stub-cortexm3-iar-efr32mg13p-rail/cbke-library-dsa-sign-stub.a" "C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v2.7//protocol/zigbee/build/cbke-library-dsa-verify-283k1-stub-cortexm3-iar-efr32mg13p-rail/cbke-library-dsa-verify-283k1-stub.a" --entry __iar_program_start --map "C:/Users/alji/SimplicityStudio/v4_workspace/Z3LightSoc/IAR ARM - Default/Z3LightSoc.map" --log_file "C:/Users/alji/SimplicityStudio/v4_workspace/Z3LightSoc/IAR ARM - Default/Z3LightSoc.log" --log initialization,modules,sections,veneers --diag_suppress=Lp012 --redirect _Printf=_PrintfSmallNoMb --redirect _Scanf=_ScanfFullNoMb  
	ielftool --srec --verbose "Z3LightSoc.out" "Z3LightSoc.s37"  
	ielftool --ihex --verbose "Z3LightSoc.out" "Z3LightSoc.hex"  
	ielftool --bin --verbose "Z3LightSoc.out" "Z3LightSoc.bin"
	@echo 'Finished building target: $@'
	@echo ' '
	$(MAKE) --no-print-directory post-build

# Other Targets
clean:
	-$(RM) $(ASM_UPPER_DEPS)$(MSA_UPPER_DEPS)$(EXECUTABLES)$(OBJS)$(ASM_DEPS)$(S79_DEPS)$(S_DEPS)$(S_UPPER_DEPS)$(MSA_DEPS)$(C_DEPS)$(S79_UPPER_DEPS) Z3LightSoc.out
	-@echo ' '

pre-build:
	-cmd //c 'C:\Users\alji\SIMPLI~1\V4_WOR~1\Z3LIGH~1/Z3LightSoc-prebuild.bat' 'Z3LightSoc' 'C:/Users/alji/SimplicityStudio/v4_workspace/Z3LightSoc' 'C:/Program Files (x86)/IAR Systems/Embedded Workbench 8.4/arm' 'C:\SiliconLabs\SimplicityStudio\v4'
	-@echo ' '

post-build:
	-cmd //c 'C:\Users\alji\SIMPLI~1\V4_WOR~1\Z3LIGH~1/Z3LightSoc-postbuild.bat' 'Z3LightSoc' 'C:/Users/alji/SimplicityStudio/v4_workspace/Z3LightSoc' 'C:/Program Files (x86)/IAR Systems/Embedded Workbench 8.4/arm' 'C:\SiliconLabs\SimplicityStudio\v4'
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY: main-build pre-build post-build

-include ../makefile.targets
