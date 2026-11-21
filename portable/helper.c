#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* The bootstrap links only to the OS C library and carries its own zipapp.
 * pkexec authorizes the sealed inode. The interpreter then reads that inode. */
int main(int argc, char **argv)
{
    const char *uid = getenv("PKEXEC_UID");
    if (argc != 2 || getuid() != 0 || geteuid() != 0 || !uid || !*uid ||
        strlen(uid) > 10 || strspn(uid, "0123456789") != strlen(uid) || strtoul(uid, NULL, 10) == 0 ||
        argv[1][0] != ':' || strlen(argv[1]) > 255) {
        fputs("更新画面から管理者の認証を行ってください。\n", stderr);
        return 1;
    }
    int fd = open("/proc/self/exe", O_RDONLY);
    int seals = fd < 0 ? -1 : fcntl(fd, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (seals < 0 || (seals & required) != required) {
        fputs("認証したヘルパーの固定済みイメージを確認できません。\n", stderr);
        return 1;
    }
    umask(0077);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || chdir("/") != 0) {
        perror("ポータブル版の実行環境");
        return 1;
    }
    char image[64], principal[32];
    snprintf(image, sizeof(image), "/proc/self/fd/%d", fd);
    snprintf(principal, sizeof(principal), "PKEXEC_UID=%s", uid);
    char *args[] = {"/usr/bin/python3", "-IBS", image, argv[1], NULL};
    char *env[] = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/", principal, NULL};
    execve(args[0], args, env);
    perror("ポータブル版の Python 起動");
    return 1;
}
