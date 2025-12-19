#include "../../inc/detector/SystemDetector.h"
#include "../inc/utils/SyscallUtils.h"
#include "../inc/utils/FileUtils.h"
#include "../inc/utils/StringUtils.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>

const std::string SystemDetector::CHECK_SYSTEM = "checkSystem_native";
const std::string SystemDetector::CHECK_KSU = "checkKsu_native";
const std::string SystemDetector::CHECK_ZYGISK = "checkZygisk_native";
const std::string SystemDetector::CHECK_PTY = "checkPty_native";
void SystemDetector::detect(JNIEnv* env, jobject callback) {
    if (!env || !callback) {
        LOGE("Invalid JNI parameters");
        return;
    }

    try {
        std::vector<std::string> abnormalDetails;

        // 1. 检查 dm-verity 状态
//        if (!checkDmVerity()) {
//            abnormalDetails.push_back("Dm-Verity is diasble");
//        }

//        // 2. 检查系统分区状态
//        if (!checkSystemPartition()) {
//            abnormalDetails.push_back("SystemPart is write");
//        }
//
//        // 3. 检查 AVB 状态
//        if (!checkAVB()) {
//            abnormalDetails.push_back("AVB diasble");
//        }

        // 4. 检查 KernelSU
        checkKsu(env, callback);

        // 5. 检查 Zygisk
        if (checkZygisk()) {
            DetectorUtils::reportWarning(
                env,
                callback,
                CHECK_ZYGISK,
                DetectorUtils::LEVEL_HIGH,
                "Zygisk Detected"
            );
        }
        checkPty(env, callback);

        // 如果发现任何异常
        if (!abnormalDetails.empty()) {
            std::string detail = "System Abnormal:\n";
            for (const auto& item : abnormalDetails) {
                detail += "- " + item + "\n";
            }
            DetectorUtils::reportWarning(
                    env,
                    callback,
                    CHECK_SYSTEM,
                    DetectorUtils::LEVEL_MEDIUM,
                    detail
            );
        }
    } catch (const std::exception& e) {
        LOGE("Error in system detection: %s", e.what());
    }
}

bool SystemDetector::checkZygisk() {
    LOGI("Starting Zygisk detection");

    pid_t child_pid = fork();
    LOGD("fork() returned: %d", child_pid);

    if (child_pid == 0) {
        // 子进程
        LOGD("Child process started");

        pid_t parent_pid = getppid();
        LOGD("Parent PID: %d", parent_pid);

        LOGD("Attempting ptrace(PTRACE_ATTACH, %d, 0, 0)", parent_pid);
        if (ptrace(PTRACE_ATTACH, parent_pid, 0, 0) == -1) {
            LOGE("ptrace(PTRACE_ATTACH) failed, errno: %d", errno);
            _exit(0);
        }
        LOGD("ptrace(PTRACE_ATTACH) successful");

        int status;
        LOGD("Calling waitpid(%d, &status, 0)", parent_pid);
        if (waitpid(parent_pid, &status, 0) == -1) {
            LOGE("waitpid() failed, errno: %d", errno);
            ptrace(PTRACE_DETACH, parent_pid, 0, 0);
            _exit(0);
        }
        LOGD("waitpid() successful, status: %d", status);

        unsigned long msg = 0;
        LOGD("Calling ptrace(PTRACE_GETEVENTMSG, %d, 0, &msg)", parent_pid);
        if (ptrace(PTRACE_GETEVENTMSG, parent_pid, 0, &msg) == -1) {
            LOGE("ptrace(PTRACE_GETEVENTMSG) failed, errno: %d", errno);
            ptrace(PTRACE_DETACH, parent_pid, 0, 0);
            _exit(0);
        }
        LOGI("ptrace(PTRACE_GETEVENTMSG) successful, msg: %lu", msg);

        LOGD("Calling ptrace(PTRACE_DETACH, %d, 0, 0)", parent_pid);
        if (ptrace(PTRACE_DETACH, parent_pid, 0, 0) == -1) {
            LOGE("ptrace(PTRACE_DETACH) failed, errno: %d", errno);
        }
        LOGD("ptrace(PTRACE_DETACH) completed");

        if (msg > 0 && msg < 65536) {
            LOGI("Zygisk DETECTED - ptrace have zygote64 pid: %lu", msg);
            _exit(1);
        } else {
            LOGI("Zygisk NOT DETECTED - ptrace message: %lu", msg);
            _exit(0);
        }
    } else if (child_pid > 0) {
        // 父进程
        LOGD("Parent process waiting for child: %d", child_pid);

        int status;
        pid_t wait_result = waitpid(child_pid, &status, 0);
        LOGD("waitpid returned: %d, status: %d", wait_result, status);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            LOGD("Child exited normally with exit code: %d", exit_code);
            bool result = (exit_code == 1);
            LOGI("Final detection result: %s", result ? "ZYGISK DETECTED" : "ZYGISK NOT DETECTED");
            return result;
        } else if (WIFSIGNALED(status)) {
            int signal_num = WTERMSIG(status);
            LOGE("Child process killed by signal: %d", signal_num);
            LOGE("Child was terminated abnormally");
        } else {
            LOGE("Child process status unknown: %d", status);
        }
    } else {
        LOGE("fork() failed, errno: %d", errno);
    }

    LOGI("Detection failed or error occurred");
    return false;
}

bool SystemDetector::checkDmVerity() {
    std::ifstream verityStatus("/sys/module/dm_verity/parameters/status");
    if (!verityStatus.is_open()) {
        return false;
    }
    std::string status;
    std::getline(verityStatus, status);
    return status.find("enabled") != std::string::npos;
}

bool SystemDetector::checkSystemPartition() {
    FILE* mounts = fopen("/proc/mounts", "r");
    if (!mounts) {
        return false;
    }

    bool isReadOnly = true;
    char line[512];
    while (fgets(line, sizeof(line), mounts)) {
        if (strstr(line, "/system") && !strstr(line, " ro,")) {
            isReadOnly = false;
            break;
        }
    }
    fclose(mounts);
    return isReadOnly;
}

bool SystemDetector::checkAVB() {
    return access("/sys/fs/avb/", F_OK) == 0;
}

// 辅助函数：去除后缀
char* strip_suffix(const char* name) {
    const char* suffix = "-8";
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);
    
    if (name_len <= suffix_len) {
        return nullptr;
    }
    
    if (strcmp(name + name_len - suffix_len, suffix) == 0) {
        char* result = (char*)malloc(name_len - suffix_len + 1);
        if (result) {
            strncpy(result, name, name_len - suffix_len);
            result[name_len - suffix_len] = '\0';
        }
        return result;
    }
    return nullptr;
}

// 辅助函数：检查目录是否存在
bool directory_exists(const char* path) {
    using namespace utils;
    int fd = FileUtils::openFile(path, O_RDONLY);
    if (fd >= 0) {
        FileUtils::closeFile(fd);
        return true;
    }
    return false;
}

void SystemDetector::checkKsu(JNIEnv* env, jobject callback) {
    using namespace utils;
    
    struct dirent *entry;
    DIR *jbd2_dir = opendir("/proc/fs/jbd2");
    if (jbd2_dir == nullptr) {
        return;
    }
    
    bool isFindKernelSu = false;
    std::string result = "find root mark: ";
    std::vector<std::string> devices;
    
    while ((entry = readdir(jbd2_dir)) != nullptr) {
        std::string entryName(entry->d_name);
        if (StringUtils::contains(entryName, "loop") && StringUtils::contains(entryName, "-8")) {
            char *device = strip_suffix(entry->d_name);
            if (device == nullptr) {
                break;
            }
            
            std::string ext4_path = "/proc/fs/ext4/" + std::string(device);
            if (directory_exists(ext4_path.c_str())) {
                isFindKernelSu = true;
                devices.push_back(std::string(device));
            }
            free(device);
        }
    }
    
    closedir(jbd2_dir);
    
    if (isFindKernelSu && !devices.empty()) {
        result += StringUtils::join(devices, " ");
        DetectorUtils::reportWarning(
            env,
            callback,
            CHECK_KSU,
            DetectorUtils::LEVEL_HIGH,
            result
        );
    }

}
#include <unistd.h>
#include <sys/stat.h>

void SystemDetector::checkPty(JNIEnv* env, jobject callback) {
    LOGI("Starting pty check (isatty method)");

    bool isSuspicious = false;
    std::string reason;

    // 方法1: 检查标准输入/输出/错误是否关联终端
    // 正常的 Android App (启动自 Launcher) 这些 fd 通常指向 /dev/null 或 logcat 管道，而不是 tty
    if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) || isatty(STDERR_FILENO)) {
        isSuspicious = true;
        reason = "Process connected to a terminal (isatty)";
    }

    // 方法2: 深度检查 /proc/self/fd 下的文件指向
    if (!isSuspicious) {
        char linkPath[256];
        char targetPath[256];

        // 检查常见的前3个 fd
        for (int i = 0; i <= 2; i++) {
            snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%d", i);
            ssize_t len = readlink(linkPath, targetPath, sizeof(targetPath) - 1);
            if (len != -1) {
                targetPath[len] = '\0';
                // 如果指向 /dev/pts/xxx，说明被 Shell/终端 控制
                if (strstr(targetPath, "/dev/pts/") != nullptr) {
                    isSuspicious = true;
                    reason = "Standard FD points to PTY: ";
                    reason += targetPath;
                    break;
                }
            }
        }
    }

    if (isSuspicious) {
        LOGI("Suspicious PTY environment detected: %s", reason.c_str());
        DetectorUtils::reportWarning(
                env,
                callback,
                CHECK_PTY,
                DetectorUtils::LEVEL_MEDIUM,
                reason
        );
    } else {
        LOGI("PTY check passed (Normal environment)");
    }
}

