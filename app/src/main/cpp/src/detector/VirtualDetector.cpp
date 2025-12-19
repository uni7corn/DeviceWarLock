#include "../../inc/detector/VirtualDetector.h"
#include "../../inc/utils/SyscallUtils.h"
#include "../../inc/utils/MiscUtil.h"

const std::string VirtualDetector::CHECK_VIRTUAL = "checkVirtual_native";
const std::string VirtualDetector::CHECK_THERMAL = "checkThermal_native";
const std::string VirtualDetector::CHECK_PROCESS = "checkProcess_native";
const std::string VirtualDetector::CHECK_BRAND_SERVICES = "checkBrandServices_native";
const std::string VirtualDetector::CHECK_ARM_REGISTERS = "checkArmRegisters_native";
void VirtualDetector::detect(JNIEnv* env, jobject callback) {
    detectArch(env, callback);
    detectThermal(env, callback);
    //detectArmRegisters(env, callback);  // 添加ARM寄存器检测

    if (MiscUtil::SystemUtils::getSDKLevel() > __ANDROID_API_Q__) {
        detectProcess(env, callback);
    }
    detectBrandServices(env, callback);  // 添加新的检测

}

void VirtualDetector::install_check_arch_seccomp() {
    struct sock_filter filter[15] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, __NR_getpid, 0, 12),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP + BPF_JEQ, DetectX86Flag, 0, 10),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_X86_64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (864 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_I386, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (386 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_ARM, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA32 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_AARCH64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA64 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (6 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog program = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter
    };

    errno = 0;
    if (utils::SyscallUtils::syscall(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
        return;
    }

    errno = 0;
    if (utils::SyscallUtils::syscall(__NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long)&program)) {
        LOGE("prctl(PR_SET_SECCOMP) failed: %s", strerror(errno));
        return;
    }
}

std::string VirtualDetector::check_arch_by_seccomp() {
    if (MiscUtil::SystemUtils::getSDKLevel() < __ANDROID_API_N_MR1__) {
        return "";
    }

    errno = 0;
    utils::SyscallUtils::syscall(__NR_getpid, DetectX86Flag);

    if (errno == 386) {
        return "I386设备";
    } else if (errno == 864) {
        return "X86_64设备";
    } else if (errno == 0xA32 || errno == 0xA64) {
        return "";  // ARM设备，正常
    } else if (errno == 0) {
        return "";  // 可能是没有开启seccomp
    }
    return std::to_string(errno);
}
void VirtualDetector::detectArch(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    install_check_arch_seccomp();
    std::string result = check_arch_by_seccomp();

    if (!result.empty()) {
        DetectorUtils::reportWarning(env, callback,
                                     CHECK_VIRTUAL,
                                     DetectorUtils::LEVEL_HIGH,
                                    result);
    }
}
void VirtualDetector::detectProcess(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    FILE* file = nullptr;
    try {
        file = popen("ps -ef", "r");
        if (!file) {
            throw std::runtime_error(std::string(strerror(errno)));
        }

        char buf[0x1000];
        std::string buffStr;
        uint32_t process_count = 0;

        while (fgets(buf, sizeof(buf), file)) {
            try {
                std::string line(buf);
                buffStr += line;

                if (!utils::StringUtils::contains(line, "xiaoc")) {
                    process_count++;
                    LOGI("ps -ef match: %s", line.c_str());
                }
            } catch (const std::exception& e) {
                LOGE("Error processing line: %s", e.what());
                continue;
            }
        }

        if (file) {
            pclose(file);
            file = nullptr;
        }

        if (process_count > MAX_NORMAL_PROCESS) {
            DetectorUtils::reportWarning(env, callback,
                                         CHECK_PROCESS,
                                         DetectorUtils::LEVEL_HIGH,
                                         buffStr);
        } else {
            LOGE("No sandbox detected in process check");
        }
    } catch (const std::exception& e) {
        if (file) {
            pclose(file);
        }
        throw; // 重新抛出异常，让上层处理
    }
}

void VirtualDetector::detectThermal(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    try {
        int thermal_count = check_thermal_zones();

        if (thermal_count == -1) {
            LOGE("Cannot access thermal zones: %s", strerror(errno));
            return;
        }

        if (thermal_count < MIN_THERMAL_ZONES) {
            std::string detail = "thermal sensor size" + std::to_string(thermal_count);

            DetectorUtils::reportWarning(env, callback,
                                         CHECK_THERMAL,
                                         DetectorUtils::LEVEL_HIGH,
                                         detail);
        } else {
            LOGI("Thermal zones check passed: found %d sensors", thermal_count);
        }
    } catch (const std::exception& e) {
        LOGE("Error in thermal detection: %s", e.what());
        // 异常情况下不抛出，只记录日志
        return;
    }
}

int VirtualDetector::check_thermal_zones() {
    DIR* dir_ptr = nullptr;
    int count = 0;

    try {
        dir_ptr = opendir("/sys/class/thermal/");
        if (!dir_ptr) {
            return -1;
        }

        struct dirent* entry;
        while ((entry = readdir(dir_ptr))) {
            if (!strcmp(entry->d_name, ".") ||
                !strcmp(entry->d_name, "..")) {
                continue;
            }
            if (strstr(entry->d_name, "thermal_zone") != nullptr) {
                count++;
            }
        }

        closedir(dir_ptr);
        return count;
    } catch (const std::exception& e) {
        if (dir_ptr) {
            closedir(dir_ptr);
        }
        throw;
    }
}
void VirtualDetector::detectBrandServices(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    // 获取手机品牌
    char brand[PROP_VALUE_MAX];
    char model[PROP_VALUE_MAX];
    __system_property_get("ro.product.brand", brand);
    __system_property_get("ro.product.model", model);
    std::string brandStr(brand);
    std::string modelStr(model);
    std::transform(brandStr.begin(), brandStr.end(), brandStr.begin(), ::tolower);
    std::transform(modelStr.begin(), modelStr.end(), modelStr.begin(), ::tolower);
    std::string serviceList = getServiceList();

    // 检查是否为iPhone
    if (brandStr.find("apple") != std::string::npos ||
        brandStr.find("iphone") != std::string::npos ||
        modelStr.find("iphone") != std::string::npos) {

        std::string detail = "You iPhone ?\n"
                             "brand: " + std::string(brand) + "\n"
                                                             "model: " + std::string(model);

        DetectorUtils::reportWarning(env, callback,
                                     CHECK_BRAND_SERVICES,
                                     DetectorUtils::LEVEL_HIGH,
                                     detail);
        return;
    }
    // 检查服务
    std::string missingServices;
    bool isAbnormal = false;

    // 检查谷歌服务
    const char* googleServices[] = {
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.apps.wellbeing",
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.apps.pixelmigrate",
            "com.google.android.apps.restore",
            "com.google.android.apps.turbo",
            "com.google.android.apps.safetyhub",
            "com.google.android.dialer"
    };
    int googleServiceCount = 0;
    for (const auto& service : googleServices) {
        if (checkServiceExists(service)) {
            googleServiceCount++;
        }
    }

    if (googleServiceCount >= 5) {
        std::string detail = "Google Service (" + std::to_string(googleServiceCount)+"/10)";
        DetectorUtils::reportWarning(env, callback,
                                     CHECK_BRAND_SERVICES,
                                     DetectorUtils::LEVEL_HIGH,
                                     detail);
        return;
    }

    if (brandStr.find("redmi") != std::string::npos ||
        modelStr.find("redmi") != std::string::npos) {
        const char* services[] = {
                "miui.redmi",
                "redmi.fingerprint",
                "redmi.face.FaceService",
                "miui.security",
                "redmi.securitycenter",
                "MiuiSystemUI",
                "redmi.camera.service",
                "miui.powerkeeper",
                "miui.memory.service",
                "security",
                "MiuiBackup",
                "MiuiBluetooth",
                "MiuiInit",
                "miuibooster",
                "miuiboosterservice",
                "MiuiSystemUI",
                "miui.securitycenter",
                "miui.face.FaceService"
        };
        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
    }// 各品牌特有服务检测
    else if (brandStr.find("xiaomi") != std::string::npos) {
        const char* services[] = {
                "miui",
                "miui.memory.service",
                "security",
                "MiuiBackup",
                "MiuiBluetooth",
                "MiuiInit",
                "miuibooster",
                "miuiboosterservice",
                "MiuiSystemUI",
                "miui.securitycenter",
                "miui.face.FaceService"
        };
        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
    }
//    else if (brandStr.find("huawei") != std::string::npos) {
//        // 华为特有服务
//        const char* services[] = {
//                "hwsys",
//                "huawei.android.launcher",
//                "HwCamCfgSvr",
//                "hwfacemanager",
//                "hwfingerprint",
//                "HwSystemManager",
//                "hwNotification"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }
//    else if (brandStr.find("oppo") != std::string::npos) {
//        // OPPO特有服务
//        const char* services[] = {
//                "oppo.face.FaceService",
//                "OppoAlgoService",
//                "oppo.fingerprints.fingerprintservice",
//                "OppoSystemUI",
//                "oppo.biometrics.fingerprint.remote",
//                "OppoBiometricsService",
//                "OppoExService"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }
//    else if (brandStr.find("vivo") != std::string::npos) {
//        // vivo特有服务
//        const char* services[] = {
//                "VivoFrameworkService",
//                "VivoSystemUIService",
//                "vivo.fingerprint.FingerprintService",
//                "VivoPhoneService",
//                "VivoSecurityService",
//                "VivoPermissionService",
//                "VivoBackupService"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }
//    else if (brandStr.find("samsung") != std::string::npos) {
//        // 三星特有服务
//        const char* services[] = {
//                "samsung.seandroid",
//                "spengestureservice",
//                "securitymanager",
//                "samsung.knox",
//                "SamsungKeyguardService",
//                "samsung.fingerprint.service",
//                "SemBnRService"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }
//    else if (brandStr.find("oneplus") != std::string::npos) {
//        // 一加特有服务
//        const char* services[] = {
//                "oneplus.face.FaceService",
//                "oneplus.fingerprint.FingerprintService",
//                "OnePlusSystemUI",
//                "oneplus.biometrics",
//                "OnePlusGestureService",
//                "oneplus.camera",
//                "OnePlusCustomizeService"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }
//    else if (brandStr.find("meizu") != std::string::npos) {
//        // 魅族特有服务
//        const char* services[] = {
//                "flyme.face",
//                "meizu.security",
//                "FlymeSystemUI",
//                "meizu.customizecenter",
//                "meizu.fingerprint",
//                "MeizuBackupService",
//                "FlymePermissionService"
//        };
//        checkServices(services, sizeof(services)/sizeof(services[0]), missingServices, isAbnormal);
//    }

    if (isAbnormal) {
        std::string detail = "brand: " + std::string(brand) + "\n" +
                             "model: " + std::string(model) + "\n" +
                             "service list:\n" + serviceList;

        DetectorUtils::reportWarning(env, callback,
                                     CHECK_BRAND_SERVICES,
                                     DetectorUtils::LEVEL_HIGH,
                                     detail);
    }
}
void VirtualDetector::checkServices(const char* services[], size_t count,
                                    std::string& missingServices, bool& isAbnormal) {
    int foundCount = 0;
    static const int MIN_REQUIRED_SERVICES = 4;

    LOGD("Starting service check, need %d of %zu services", MIN_REQUIRED_SERVICES, count);

    for (size_t i = 0; i < count; i++) {
        if (checkServiceExists(services[i])) {
            foundCount++;
            LOGD("Found service[%d/%zu]: %s", foundCount, count, services[i]);
            if (foundCount >= MIN_REQUIRED_SERVICES) {
                LOGD("Found enough services (%d), marking as normal", foundCount);
                isAbnormal = false;
                return;
            }
        } else {
            LOGD("Missing service: %s", services[i]);
            missingServices += services[i];
            missingServices += "\n";
        }
    }

    LOGD("Found only %d/%zu services, marking as abnormal", foundCount, count);
    isAbnormal = true;
    missingServices = "找到特征服务: " + std::to_string(foundCount) +
                      "/" + std::to_string(count) + "\n" +
                      "缺失的服务:\n" + missingServices;
}
std::string VirtualDetector::getServiceList() {
    FILE* pipe = popen("service list", "r");
    if (!pipe) {
        LOGE("Failed to execute service list command: %s", strerror(errno));
        return "无法获取服务列表";
    }

    char buffer[128];
    std::string result;

    while (!feof(pipe)) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    }

    int status = pclose(pipe);
    if (status != 0) {
        LOGE("service list command failed with status: %d", status);
    }

    if (result.empty()) {
        LOGE("Got empty service list");
    } else {
        LOGD("Got service list with length: %zu", result.length());
    }

    return result;
}
bool VirtualDetector::checkServiceExists(const char* serviceName) {
    // 缓存原始服务列表和小写版本
    static std::string serviceList = getServiceList();
    static std::string lowerServiceList = serviceList;  // 缓存小写版本
    static bool initialized = false;

    // 第一次调用时转换为小写
    if (!initialized) {
        std::transform(lowerServiceList.begin(), lowerServiceList.end(),
                       lowerServiceList.begin(), ::tolower);
        initialized = true;
    }

    // 只需转换查询的服务名为小写
    std::string name(serviceName);
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    return lowerServiceList.find(name) != std::string::npos;
}

// ARM寄存器检测实现
void VirtualDetector::detectArmRegisters(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    try {
        std::string hardwareInfo = analyzeArmHardware();
        
        if (!hardwareInfo.empty()) {
            DetectorUtils::reportWarning(env, callback,
                                         CHECK_ARM_REGISTERS,
                                         DetectorUtils::LEVEL_HIGH,
                                         hardwareInfo);
        } else {
            LOGI("ARM hardware registers check passed");
        }
    } catch (const std::exception& e) {
        LOGE("Error in ARM registers detection: %s", e.what());
        return;
    }
}

uint64_t VirtualDetector::getMainIdRegister() {
    uint64_t register_value = 0;
#ifdef __aarch64__
    asm volatile(
            "mrs %0, MIDR_EL1\n"
            : "=r" (register_value)
            );
#elif defined(__arm__)
    uint32_t reg_val;
    asm volatile(
            "mrc p15, 0, %0, c0, c0, 0\n"
            : "=r" (reg_val)
            );
    register_value = reg_val;
#endif
    return register_value;
}

uint64_t VirtualDetector::getMultiprocessorAffinityRegister() {
    uint64_t register_value = 0;
#ifdef __aarch64__
    asm volatile(
            "mrs %0, MPIDR_EL1\n"
            : "=r" (register_value)
            );
#elif defined(__arm__)
    uint32_t reg_val;
    asm volatile(
            "mrc p15, 0, %0, c0, c0, 5\n"
            : "=r" (reg_val)
            );
    register_value = reg_val;
#endif
    return register_value;
}

uint64_t VirtualDetector::getRevisionIdRegister() {
    uint64_t register_value = 0;
#ifdef __aarch64__
    asm volatile(
            "mrs %0, REVIDR_EL1\n"
            : "=r" (register_value)
            );
#elif defined(__arm__)
    uint32_t reg_val;
    asm volatile(
            "mrc p15, 0, %0, c0, c0, 6\n"
            : "=r" (reg_val)
            );
    register_value = reg_val;
#endif
    return register_value;
}

uint64_t VirtualDetector::getProcessorFeatureRegister0() {
    uint64_t register_value = 0;
#ifdef __aarch64__
    asm volatile(
            "mrs %0, ID_AA64PFR0_EL1\n"
            : "=r" (register_value)
            );
#elif defined(__arm__)
    uint32_t reg_val;
    asm volatile(
            "mrc p15, 0, %0, c0, c1, 0\n"
            : "=r" (reg_val)
            );
    register_value = reg_val;
#endif
    return register_value;
}

uint64_t VirtualDetector::getInstructionSetAttributeRegister0() {
    uint64_t register_value = 0;
#ifdef __aarch64__
    asm volatile(
            "mrs %0, ID_AA64ISAR0_EL1\n"
            : "=r" (register_value)
            );
#elif defined(__arm__)
    uint32_t reg_val;
    asm volatile(
            "mrc p15, 0, %0, c0, c2, 0\n"
            : "=r" (reg_val)
            );
    register_value = reg_val;
#endif
    return register_value;
}

std::string VirtualDetector::analyzeArmHardware() {
    std::stringstream anomalies;
    
    try {
        uint64_t midr_value = getMainIdRegister();
        unsigned char implementer_code = (midr_value >> 24) & 0xFF;
        unsigned int part_number = (midr_value >> 4) & 0xFFF;
        
        // 检测可疑的实现者代码
        if (implementer_code == 0x69) {  // Intel Corporation
            anomalies << "检测到Intel实现者代码(0x69)，可能为x86虚拟化环境\n";
        }
        
        // 检测异常的部件号
        if (part_number == 0x000 || part_number == 0xFFF) {
            anomalies << "检测到异常的部件号: 0x" << std::hex << part_number << std::dec << "\n";
        }
        
        uint64_t mpidr_value = getMultiprocessorAffinityRegister();
        unsigned int core_id = mpidr_value & 0xFF;
        unsigned int cluster_id = (mpidr_value >> 8) & 0xFF;
        
        // 检测异常的核心配置
        if (core_id > 16 || cluster_id > 8) {
            anomalies << "检测到异常的核心配置 - Core ID: " << core_id 
                     << ", Cluster ID: " << cluster_id << "\n";
        }
        
        uint64_t pfr0_value = getProcessorFeatureRegister0();
        unsigned int fp_support = (pfr0_value >> 16) & 0xF;
        unsigned int asimd_support = (pfr0_value >> 20) & 0xF;
        
        // 检测缺失的浮点支持（真实ARM设备通常都有）
        if (fp_support == 0x0) {
            anomalies << "检测到缺失浮点支持，可能为虚拟环境\n";
        }
        
        if (asimd_support == 0x0) {
            anomalies << "检测到缺失ASIMD支持，可能为虚拟环境\n";
        }
        
        uint64_t isar0_value = getInstructionSetAttributeRegister0();
        unsigned int aes_support = (isar0_value >> 4) & 0xF;
        unsigned int sha1_support = (isar0_value >> 8) & 0xF;
        
        // 检测加密指令支持异常
        if (aes_support == 0x0 && sha1_support == 0x0) {
            anomalies << "检测到缺失加密指令支持，可能为虚拟环境\n";
        }
        
        // 添加详细的硬件信息用于分析
        if (!anomalies.str().empty()) {
            std::stringstream detail;
            detail << "ARM硬件异常检测:\n" << anomalies.str() << "\n";
            detail << "详细信息:\n";
            detail << "MIDR_EL1: 0x" << std::hex << midr_value << std::dec;
            detail << " (实现者: 0x" << std::hex << (unsigned int)implementer_code << std::dec;
            detail << ", 部件: 0x" << std::hex << part_number << std::dec << ")\n";
            detail << "MPIDR_EL1: 0x" << std::hex << mpidr_value << std::dec;
            detail << " (核心: " << core_id << ", 集群: " << cluster_id << ")\n";
            detail << "PFR0: 0x" << std::hex << pfr0_value << std::dec;
            detail << " (FP: " << fp_support << ", ASIMD: " << asimd_support << ")\n";
            detail << "ISAR0: 0x" << std::hex << isar0_value << std::dec;
            detail << " (AES: " << aes_support << ", SHA1: " << sha1_support << ")";
            
            return detail.str();
        }
        
    } catch (const std::exception& e) {
        LOGE("Error reading ARM registers: %s", e.what());
        return "ARM寄存器读取失败: " + std::string(e.what());
    }
    
    return "";  // 没有检测到异常
}