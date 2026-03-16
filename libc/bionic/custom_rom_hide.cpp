/*
 * Copyright (C) 2025 AxionOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "custom_rom_hide.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <private/android_filesystem_config.h>
struct PrefixEntry {
    const char* str;
    size_t len;
};
#define PE(s) { s, sizeof(s) - 1 }

static const char* const kBlockedBasenames[] = {
    "su", "daemonsu", "su-backup", ".su",
    "magisk", "magiskhide", "magiskpolicy", "magiskinit", "magiskboot",
    "busybox", "supolicy", "mu",
    "ksud", "apd",
    nullptr
};

static const char* const kBinaryDirs[] = {
    "/system/bin", "/system/xbin", "/sbin",
    "/su/bin", "/su/xbin",
    "/system/bin/failsafe", "/system/bin/.ext",
    "/system/sd/xbin", "/system/usr/we-need-root",
    "/data/local/bin", "/data/local/xbin", "/data/local",
    nullptr
};

static const char* const kBlockedExactPaths[] = {
    "/su",
    "/su/bin",
    "/su/xbin",
    "/system/bin/.ext",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/app/SuperSU",
    "/system/etc/.installed_su_daemon",
    "/system/etc/.has_su_daemon",
    "/system/etc/init.d/99telesu",
    "/system/bin/install-recovery.sh",
    "/dev/magisk",
    "/cache/magisk.log",
    "/data/cache/magisk.log",
    "/sbin/recovery",
    "/tmp/recovery.log",
    nullptr
};

static const PrefixEntry kBlockedPrefixes[] = {
    PE("/data/adb/"),
    {nullptr, 0}
};

static const char* const kBlockedDirnames[] = {
    "addon.d",
    "init.d",
    "TWRP",
    nullptr
};

static const char* const kDirParents[] = {
    "/system", "/system/etc",
    "/system_ext", "/system_ext/etc",
    "/product", "/product/etc",
    "/vendor", "/vendor/etc",
    "/sdcard", "/data/media/0",
    nullptr
};

static const PrefixEntry kRecoveryPrefixes[] = {
    PE("/cache/recovery/"),
    {nullptr, 0}
};

static const char* const kBlockedPackages[] = {
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "me.weishu.kernelsu",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.chelpus.luckypatcher",
    "com.solohsu.android.edxp.manager",
    "org.meowcat.edxposed.manager",
    "org.lsposed.manager",
    "cc.madkite.freedom",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.zachspong.temprootremovejb",
    nullptr
};

static const char* const kDataDirPrefixes[] = {
    "/data/data/",
    "/data/user/0/",
    "/data/user_de/0/",
    nullptr
};

static bool is_blocked_package_path(const char* path) {
    for (const char* const* prefix = kDataDirPrefixes; *prefix; ++prefix) {
        size_t plen = strlen(*prefix);
        if (strncmp(path, *prefix, plen) != 0) continue;
        const char* remainder = path + plen;
        for (const char* const* pkg = kBlockedPackages; *pkg; ++pkg) {
            size_t pkglen = strlen(*pkg);
            if (strncmp(remainder, *pkg, pkglen) == 0 &&
                (remainder[pkglen] == '\0' || remainder[pkglen] == '/')) {
                return true;
            }
        }
    }
    return false;
}

static const char* const kProcFilterKeywords[] = {
    "magisk",
    "zygisk",
    "/data/adb",
    "/debug_ramdisk",
    "lineage",
    "Lineage",
    "axion",
    "Axion",
    "omnirom",
    nullptr
};

static const char* const kMountFilterKeywords[] = {
    "magisk",
    "KSU",
    "APatch",
    "/data/adb",
    "/debug_ramdisk",
    "overlay",
    nullptr
};

static bool g_resolved = false;
static bool g_allowed = false;

static inline int raw_openat(const char* path, int flags) {
    return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
}

static inline ssize_t raw_read(int fd, void* buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static inline ssize_t raw_write(int fd, const void* buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static inline int raw_close(int fd) {
    return static_cast<int>(syscall(__NR_close, fd));
}

static inline ssize_t raw_readlinkat(const char* path, char* buf, size_t size) {
    return syscall(__NR_readlinkat, AT_FDCWD, path, buf, size);
}

static inline off_t raw_lseek(int fd, off_t offset, int whence) {
    return syscall(__NR_lseek, fd, offset, whence);
}

static inline int raw_memfd_create(const char* name, unsigned int flags) {
    return static_cast<int>(syscall(__NR_memfd_create, name, flags));
}


static bool is_allowed() {
    if ((getuid() % AID_USER_OFFSET) < AID_APP_START) return true;
    if (g_resolved) return g_allowed;
    g_resolved = true;
    g_allowed = false;
    return false;
}

static const char* path_basename(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}


static bool path_parent_equals(const char* path, const char* parent) {
    size_t plen = strlen(parent);
    if (strncmp(path, parent, plen) != 0) return false;
    return path[plen] == '/';
}

static bool is_blocked_binary(const char* path) {
    const char* base = path_basename(path);
    for (const char* const* b = kBlockedBasenames; *b; ++b) {
        if (strcmp(base, *b) != 0) continue;
        for (const char* const* d = kBinaryDirs; *d; ++d) {
            if (path_parent_equals(path, *d)) return true;
        }
    }
    return false;
}

static bool is_blocked_dir(const char* path) {
    const char* base = path_basename(path);
    for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
        if (strcmp(base, *dn) != 0) continue;
        for (const char* const* pp = kDirParents; *pp; ++pp) {
            if (path_parent_equals(path, *pp)) return true;
        }
    }
    return false;
}


static bool is_root_path(const char* path) {
    if (!path || path[0] != '/') return false;

    size_t len = strlen(path);
    bool has_trailing = len > 1 && path[len - 1] == '/';
    char stack_buf[512];
    const char* clean = path;
    if (has_trailing) {
        if (len >= sizeof(stack_buf)) len = sizeof(stack_buf) - 1;
        memcpy(stack_buf, path, len);
        while (len > 1 && stack_buf[len - 1] == '/') len--;
        stack_buf[len] = '\0';
        clean = stack_buf;
    }

    for (const PrefixEntry* p = kBlockedPrefixes; p->str; ++p) {
        if (strncmp(clean, p->str, p->len) == 0) return true;
    }

    for (const char* const* p = kBlockedExactPaths; *p; ++p) {
        if (strcmp(clean, *p) == 0) return true;
    }

    for (const PrefixEntry* p = kRecoveryPrefixes; p->str; ++p) {
        if (strncmp(clean, p->str, p->len) == 0) return true;
    }

    if (is_blocked_binary(clean)) return true;
    if (is_blocked_dir(clean)) return true;
    if (is_blocked_package_path(clean)) return true;

    return false;
}

static bool resolve_fd_path(int fd, char* buf, size_t size) {
    char proc_link[64];
    snprintf(proc_link, sizeof(proc_link), "/proc/self/fd/%d", fd);
    ssize_t n = raw_readlinkat(proc_link, buf, size - 1);
    if (n > 0) {
        buf[n] = '\0';
        return true;
    }
    return false;
}

static bool could_be_blocked_path(const char* path) {
    if (!path || path[0] != '/') return false;
    char c = path[1];
    return c == 's' || c == 'd' || c == 'c' || c == 't' || c == 'p' || c == 'S';
}

bool custom_rom_hide_should_block(const char* path) {
    if (!could_be_blocked_path(path)) return false;
    if (is_allowed()) return false;
    return is_root_path(path);
}

bool custom_rom_hide_should_block_at(int dirfd, const char* path) {
    if (!path) return false;

    if (path[0] == '/') {
        return custom_rom_hide_should_block(path);
    }

    if (dirfd == AT_FDCWD) return false;

    char dir_path[256];
    if (!resolve_fd_path(dirfd, dir_path, sizeof(dir_path))) return false;

    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, path);
    return custom_rom_hide_should_block(full_path);
}

bool custom_rom_hide_should_filter_dirent(int dirfd, const char* name) {
    if (!name || is_allowed()) return false;

    char dir_path[256];
    if (!resolve_fd_path(dirfd, dir_path, sizeof(dir_path))) return false;

    for (const char* const* d = kBinaryDirs; *d; ++d) {
        if (strcmp(dir_path, *d) != 0) continue;
        for (const char* const* b = kBlockedBasenames; *b; ++b) {
            if (strcmp(name, *b) == 0) return true;
        }
        return false;
    }

    for (const char* const* pp = kDirParents; *pp; ++pp) {
        if (strcmp(dir_path, *pp) != 0) continue;
        for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
            if (strcmp(name, *dn) == 0) return true;
        }
        return false;
    }

    return false;
}

enum ProcFilterType {
    PROC_FILTER_NONE,
    PROC_FILTER_MAPS,
    PROC_FILTER_MOUNTS,
    PROC_FILTER_MOUNTINFO,
    PROC_FILTER_UNIX,
    PROC_FILTER_FILESYSTEMS,
};

static ProcFilterType get_proc_filter_type(const char* path) {
    if (!path) return PROC_FILTER_NONE;

    char pid_path[64];
    snprintf(pid_path, sizeof(pid_path), "/proc/%d/", static_cast<int>(getpid()));

    const char* leaf = nullptr;

    if (strncmp(path, "/proc/self/", 11) == 0) {
        leaf = path + 11;
    } else if (strncmp(path, pid_path, strlen(pid_path)) == 0) {
        leaf = path + strlen(pid_path);
    } else if (strcmp(path, "/proc/net/unix") == 0) {
        return PROC_FILTER_UNIX;
    } else if (strcmp(path, "/proc/filesystems") == 0) {
        return PROC_FILTER_FILESYSTEMS;
    } else if (strcmp(path, "/proc/1/mountinfo") == 0) {
        return PROC_FILTER_MOUNTINFO;
    }

    if (!leaf) return PROC_FILTER_NONE;

    if (strcmp(leaf, "maps") == 0) return PROC_FILTER_MAPS;
    if (strcmp(leaf, "mounts") == 0) return PROC_FILTER_MOUNTS;
    if (strcmp(leaf, "mountinfo") == 0) return PROC_FILTER_MOUNTINFO;

    return PROC_FILTER_NONE;
}

static bool line_contains_any(const char* line, const char* const* keywords) {
    for (const char* const* kw = keywords; *kw; ++kw) {
        if (strstr(line, *kw) != nullptr) return true;
    }
    return false;
}

static bool is_magisk_unix_socket(const char* line) {
    const char* at = strrchr(line, '@');
    if (!at) return false;

    const char* name = at + 1;
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '\n') len--;
    if (len < 32) return false;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        bool is_alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9');
        if (!is_alnum) return false;
    }
    return true;
}

static bool should_filter_line(ProcFilterType type, const char* line) {
    switch (type) {
        case PROC_FILTER_MAPS:
            return line_contains_any(line, kProcFilterKeywords);
        case PROC_FILTER_MOUNTS:
            if (line_contains_any(line, kMountFilterKeywords)) return true;
            if (strstr(line, "tmpfs") && strstr(line, "/sbin")) return true;
            return false;
        case PROC_FILTER_MOUNTINFO:
            return line_contains_any(line, kMountFilterKeywords);
        case PROC_FILTER_UNIX:
            return is_magisk_unix_socket(line);
        case PROC_FILTER_FILESYSTEMS:
            return strstr(line, "overlay") != nullptr
                || strstr(line, "fuse") != nullptr;
        default:
            return false;
    }
}

static char* read_file_raw(const char* path, size_t* out_size) {
    int fd = raw_openat(path, O_RDONLY);
    if (fd < 0) return nullptr;

    size_t capacity = 16384;
    size_t size = 0;
    char* buf = static_cast<char*>(malloc(capacity));
    if (!buf) {
        raw_close(fd);
        return nullptr;
    }

    ssize_t n;
    while ((n = raw_read(fd, buf + size, capacity - size - 1)) > 0) {
        size += n;
        if (size >= capacity - 1) {
            capacity *= 2;
            char* new_buf = static_cast<char*>(realloc(buf, capacity));
            if (!new_buf) {
                free(buf);
                raw_close(fd);
                return nullptr;
            }
            buf = new_buf;
        }
    }
    raw_close(fd);

    buf[size] = '\0';
    *out_size = size;
    return buf;
}

int custom_rom_hide_filter_proc(const char* path) {
    if (is_allowed()) return -1;

    ProcFilterType type = get_proc_filter_type(path);
    if (type == PROC_FILTER_NONE) return -1;

    size_t file_size = 0;
    char* content = read_file_raw(path, &file_size);
    if (!content) return -1;

    int mem_fd = raw_memfd_create("proc", 0);
    if (mem_fd < 0) {
        free(content);
        return -1;
    }

    char* pos = content;
    while (*pos) {
        char* eol = strchr(pos, '\n');
        size_t line_len;
        if (eol) {
            line_len = eol - pos + 1;
        } else {
            line_len = strlen(pos);
        }

        char saved = pos[line_len];
        pos[line_len] = '\0';

        if (!should_filter_line(type, pos)) {
            raw_write(mem_fd, pos, line_len);
        }

        pos[line_len] = saved;
        pos += line_len;
    }

    free(content);
    raw_lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static const char* const kSepolicyFilterPaths[] = {
    "/system/etc/selinux/plat_service_contexts",
    "/system/etc/selinux/plat_seapp_contexts",
    "/system/etc/selinux/plat_file_contexts",
    "/system/etc/selinux/plat_property_contexts",
    "/system/etc/selinux/plat_sepolicy.cil",
    "/system_ext/etc/selinux/system_ext_service_contexts",
    "/system_ext/etc/selinux/system_ext_seapp_contexts",
    "/system_ext/etc/selinux/system_ext_file_contexts",
    "/system_ext/etc/selinux/system_ext_property_contexts",
    "/system_ext/etc/selinux/system_ext_sepolicy.cil",
    "/product/etc/selinux/product_service_contexts",
    "/product/etc/selinux/product_seapp_contexts",
    "/product/etc/selinux/product_file_contexts",
    "/product/etc/selinux/product_property_contexts",
    "/vendor/etc/selinux/vendor_file_contexts",
    "/vendor/etc/selinux/vendor_service_contexts",
    "/vendor/etc/selinux/vendor_hwservice_contexts",
    "/vendor/etc/selinux/vendor_property_contexts",
    "/vendor/etc/selinux/vendor_sepolicy.cil",
    "/vendor/etc/selinux/plat_pub_versioned.cil",
    nullptr
};

static bool is_sepolicy_context_file(const char* path) {
    for (const char* const* p = kSepolicyFilterPaths; *p; ++p) {
        if (strcmp(path, *p) == 0) return true;
    }
    return false;
}

int custom_rom_hide_filter_sepolicy(const char* path) {
    if (is_allowed()) return -1;
    if (!is_sepolicy_context_file(path)) return -1;

    size_t file_size = 0;
    char* content = read_file_raw(path, &file_size);
    if (!content) return -1;

    int mem_fd = raw_memfd_create("sectx", 0);
    if (mem_fd < 0) {
        free(content);
        return -1;
    }

    char* pos = content;
    while (*pos) {
        char* eol = strchr(pos, '\n');
        size_t line_len;
        if (eol) {
            line_len = eol - pos + 1;
        } else {
            line_len = strlen(pos);
        }

        char saved = pos[line_len];
        pos[line_len] = '\0';

        bool filter = (strstr(pos, "lineage") != nullptr);

        pos[line_len] = saved;

        if (!filter) {
            raw_write(mem_fd, pos, line_len);
        }

        pos += line_len;
    }

    free(content);
    raw_lseek(mem_fd, 0, SEEK_SET);
    return mem_fd;
}

static const char* const kSpoofedEmptyProps[] = {
    "ro.axion.version",
    "ro.lineage.version",
    "ro.lineage.build.version",
    "ro.cm.build.version",
    "ro.modversion",
    "init.svc.magisk_daemon",
    "persist.magisk.hide",
    "service.adb.root",
    nullptr
};

struct PropOverride {
    const char* name;
    const char* value;
};

static const PropOverride kSpoofedValueProps[] = {
    {"ro.debuggable", "0"},
    {"ro.build.type", "user"},
    {"ro.adb.secure", "1"},
    {"persist.sys.usb.config", "mtp"},
    {nullptr, nullptr}
};

bool custom_rom_hide_should_spoof_prop(const char* name, char* value) {
    if (!name || is_allowed()) return false;

    for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
        if (strcmp(name, *p) == 0) {
            value[0] = '\0';
            return true;
        }
    }

    for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) {
            strcpy(value, o->value);
            return true;
        }
    }

    return false;
}

bool custom_rom_hide_should_hide_prop(const char* name) {
    if (!name || is_allowed()) return false;

    for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
        if (strcmp(name, *p) == 0) return true;
    }
    return false;
}

const char* custom_rom_hide_get_prop_override(const char* name) {
    if (!name || is_allowed()) return nullptr;

    for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) return o->value;
    }
    return nullptr;
}
