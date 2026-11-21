#define _GNU_SOURCE
#include "portable.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif

static void system_error(GError **error, const char *message)
{
    int saved = errno;
    g_set_error(error, G_IO_ERROR, g_io_error_from_errno(saved), "%s\n%s", message, g_strerror(saved));
}

int portable_take_appdir(void)
{
    const char *handle = g_getenv("MKNK_BIOS_PORTABLE_DIR_FD");
    guint64 fd;
    struct stat st;
    if (!handle || !g_ascii_string_to_unsigned(handle, 10, 3, G_MAXINT, &fd, NULL))
        return -1;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) ||
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;
    return (int) fd;
}

void portable_reopen(int dir_fd, GError **error)
{
    int flags = fcntl(dir_fd, F_GETFD);
    if (flags >= 0 && fcntl(dir_fd, F_SETFD, flags & ~FD_CLOEXEC) == 0) {
        /* Keep the AppImage runtime/mount and its original directory alive. */
        execl("/proc/self/exe", "mknk-bios-update", "--open-plan", (char *) NULL);
        system_error(error, "通常モードで開き直せませんでした。");
        fcntl(dir_fd, F_SETFD, flags);
    } else {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "元の AppImage をもう一度開いてください。");
    }
}

static int sealed_helper(int dir_fd, GError **error)
{
    int source = openat(dir_fd, "usr/lib/mknk-bios-update/portable-helper",
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source < 0) {
        system_error(error, "AppImage 内の端末サービスを開けません。元の配布ファイルを確認してください。");
        return -1;
    }
    struct stat st;
    if (fstat(source, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(source);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "AppImage 内の端末サービスを読み取れません。");
        return -1;
    }
    int image = memfd_create("mknk-bios-update-helper", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
    if (image < 0 && errno == EINVAL)
        image = memfd_create("mknk-bios-update-helper", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (image < 0) goto failed;
    char buffer[65536];
    for (off_t left = st.st_size; left > 0; ) {
        ssize_t got;
        do { got = read(source, buffer, MIN((off_t) sizeof buffer, left)); } while (got < 0 && errno == EINTR);
        if (got == 0) errno = EIO;
        if (got <= 0) goto failed;
        for (ssize_t offset = 0; offset < got; ) {
            ssize_t written = write(image, buffer + offset, got - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written == 0) errno = EIO;
            if (written <= 0) goto failed;
            offset += written;
        }
        left -= got;
    }
    if (fchmod(image, 0500) < 0 || lseek(image, 0, SEEK_SET) < 0) goto failed;
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fcntl(image, F_ADD_SEALS, seals | F_SEAL_EXEC) < 0 &&
        (errno != EINVAL || fcntl(image, F_ADD_SEALS, seals) < 0))
        goto failed;
    close(source);
    return image;

failed:
    system_error(error, "このカーネルでは端末サービスの実行用コピーを保護できません。");
    if (image >= 0) close(image);
    close(source);
    return -1;
}

/* Drain stderr for the entire life of the child. Retain only a short startup
 * diagnostic, and keep /proc/<gui>/fd/<image> valid until pkexec has exited. */
typedef struct {
    GSubprocess *process;
    int image;
    GMutex mutex;
    GCond exited;
    gboolean done;
    char reason[2048];
} Helper;

static void helper_clear(gpointer data)
{
    Helper *helper = data;
    g_mutex_clear(&helper->mutex);
    g_cond_clear(&helper->exited);
    g_object_unref(helper->process);
}

static void helper_unref(gpointer helper)
{
    g_atomic_rc_box_release_full(helper, helper_clear);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(Helper, helper_unref)

static gpointer monitor_helper(gpointer data)
{
    g_autoptr(Helper) helper = data;
    GInputStream *stream = g_subprocess_get_stderr_pipe(helper->process);
    char buffer[1024];
    gsize used = 0;
    gssize count;
    while ((count = g_input_stream_read(stream, buffer, sizeof buffer, NULL, NULL)) > 0) {
        gsize keep = MIN((gsize) count, sizeof helper->reason - 1 - used);
        memcpy(helper->reason + used, buffer, keep);
        used += keep;
    }
    g_subprocess_wait(helper->process, NULL, NULL);
    close(helper->image);
    g_mutex_lock(&helper->mutex);
    helper->done = TRUE;
    g_cond_signal(&helper->exited);
    g_mutex_unlock(&helper->mutex);
    return NULL;
}

static void start_error(Helper *helper, GError **error)
{
    gint64 deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    g_mutex_lock(&helper->mutex);
    while (!helper->done && g_cond_wait_until(&helper->exited, &helper->mutex, deadline)) {}
    int status = helper->done && g_subprocess_get_if_exited(helper->process)
               ? g_subprocess_get_exit_status(helper->process) : -1;
    g_autofree char *diagnostic = helper->done ? g_utf8_make_valid(helper->reason, -1) : NULL;
    g_mutex_unlock(&helper->mutex);
    const char *reason = status == 126 ? "管理者認証を取り消しました。" :
                         status == 127 ? "管理者認証を完了できません。デスクトップの認証エージェントを確認してください。" :
                         "端末サービスを起動できません。";
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s%s%s", reason,
                diagnostic && *g_strstrip(diagnostic) ? "\n" : "", diagnostic ? diagnostic : "");
}

static char *read_address(Helper *helper, GCancellable *cancel, GError **error)
{
    GInputStream *out = g_subprocess_get_stdout_pipe(helper->process);
    char line[1024];
    for (gsize n = 0; n < sizeof line; n++) {
        gssize got = g_input_stream_read(out, &line[n], 1, cancel, error);
        if (got < 0) return NULL;
        if (got == 0) {
            start_error(helper, error);
            return NULL;
        }
        if (line[n] == '\n') return g_strndup(line, n);
        if (line[n] == '\0') break;
    }
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "端末サービスの接続先を読み取れません。");
    return NULL;
}

static gboolean local_address(const char *address)
{
    if (!g_str_has_prefix(address, "unix:") || strchr(address, ';') || !g_dbus_is_address(address))
        return FALSE;
    g_auto(GStrv) parts = g_strsplit(address + strlen("unix:"), ",", -1);
    gboolean location = FALSE, guid = FALSE;
    for (guint i = 0; parts[i]; i++) {
        const char *part = parts[i];
        if (g_str_has_prefix(part, "guid=") && !guid && g_dbus_is_guid(part + 5)) {
            guid = TRUE;
            continue;
        }
        gboolean path = g_str_has_prefix(part, "path=");
        if (location || (!path && !g_str_has_prefix(part, "abstract="))) return FALSE;
        g_autofree char *name = g_uri_unescape_string(strchr(part, '=') + 1, NULL);
        if (!name || !*name) return FALSE;
        if (path) {
            g_autofree char *canonical = g_canonicalize_filename(name, NULL);
            if (!g_str_has_prefix(name, "/run/") || !g_str_equal(name, canonical)) return FALSE;
        }
        location = TRUE;
    }
    return location;
}

static GDBusConnection *connect_root(const char *address, GCancellable *cancel, GError **error)
{
    if (!local_address(address)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "端末サービスの接続先が正しくありません。");
        return NULL;
    }
    g_autofree char *guid = NULL;
    g_autoptr(GIOStream) stream = g_dbus_address_get_stream_sync(address, &guid, cancel, error);
    if (!stream) return NULL;
    GSocket *sock = G_IS_SOCKET_CONNECTION(stream) ? g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)) : NULL;
    struct ucred cred;
    socklen_t size = sizeof cred;
    if (!sock || g_socket_get_family(sock) != G_SOCKET_FAMILY_UNIX ||
        getsockopt(g_socket_get_fd(sock), SOL_SOCKET, SO_PEERCRED, &cred, &size) != 0 ||
        size != sizeof cred || cred.uid != 0 || cred.pid <= 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "接続先の管理者権限を確認できません。");
        return NULL;
    }
    g_autoptr(GDBusConnection) peer = g_dbus_connection_new_sync(stream, NULL,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, cancel, error);
    if (peer && guid && g_strcmp0(guid, g_dbus_connection_get_guid(peer)) != 0) {
        g_dbus_connection_close_sync(peer, NULL, NULL);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "端末サービスの識別情報が一致しません。");
        return NULL;
    }
    return g_steal_pointer(&peer);
}

static void connect_thread(GTask *task, gpointer source, gpointer data, GCancellable *cancel)
{
    (void) source;
    Helper *helper = data;
    g_autoptr(GError) error = NULL;
    g_autofree char *address = read_address(helper, cancel, &error);
    GDBusConnection *peer = address ? connect_root(address, cancel, &error) : NULL;
    if (peer) {
        g_dbus_connection_set_exit_on_close(peer, FALSE);
        g_task_return_pointer(task, peer, g_object_unref);
    } else {
        g_subprocess_force_exit(helper->process);
        g_task_return_error(task, g_steal_pointer(&error));
    }
}

static void close_image(gpointer encoded_fd)
{
    close(GPOINTER_TO_INT(encoded_fd) - 1);
}

static void copy_thread(GTask *task, gpointer source, gpointer data, GCancellable *cancel)
{
    (void) source; (void) cancel;
    if (g_task_return_error_if_cancelled(task)) return;
    g_autoptr(GError) error = NULL;
    int image = sealed_helper(GPOINTER_TO_INT(data), &error);
    if (image < 0)
        g_task_return_error(task, g_steal_pointer(&error));
    else
        g_task_return_pointer(task, GINT_TO_POINTER(image + 1), close_image);
}

static void helper_prepared(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(GTask) task = data;
    g_autoptr(GError) error = NULL;
    int image = GPOINTER_TO_INT(g_task_propagate_pointer(G_TASK(result), &error)) - 1;
    if (error) {
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }
    if (g_task_return_error_if_cancelled(task)) {
        close(image);
        return;
    }
    GDBusConnection *system = G_DBUS_CONNECTION(source);
    const char *name = g_dbus_connection_get_unique_name(system);
    if (!name || !g_dbus_is_unique_name(name) || g_dbus_connection_is_closed(system)) {
        close(image);
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CLOSED, "この画面のシステムバス接続を確認できません。");
        return;
    }
    /* Linux pkexec ties its lifetime to the thread that spawned it. Launch on
     * the GTK main thread, which lives until the window and its work exit. */
    g_autofree char *program = g_strdup_printf("/proc/%ld/fd/%d", (long) getpid(), image);
    g_autoptr(GSubprocessLauncher) launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                                                       G_SUBPROCESS_FLAGS_STDERR_PIPE);
    /* pkexec and the privileged program must resolve their own host libraries. */
    char *env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    g_subprocess_launcher_set_environ(launcher, env);
    const char *lang = g_getenv("LANG");
    if (lang) g_subprocess_launcher_setenv(launcher, "LANG", lang, TRUE);
    GSubprocess *process = g_subprocess_launcher_spawn(launcher, &error, "/usr/bin/pkexec", "--disable-internal-agent",
                                                        program, name, NULL);
    if (!process) {
        close(image);
        g_prefix_error(&error, "管理者認証を起動できません。端末の pkexec を確認してください。\n");
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }
    Helper *helper = g_atomic_rc_box_new0(Helper);
    helper->process = process;
    helper->image = image;
    g_mutex_init(&helper->mutex);
    g_cond_init(&helper->exited);
    g_thread_unref(g_thread_new("portable-helper", monitor_helper, g_atomic_rc_box_acquire(helper)));
    g_task_set_task_data(task, helper, helper_unref);
    g_task_run_in_thread(task, connect_thread);
}

static void close_dir(gpointer data)
{
    close(GPOINTER_TO_INT(data));
}

void portable_connect_async(GDBusConnection *system, int dir_fd, GCancellable *cancel,
                            GAsyncReadyCallback callback, gpointer data)
{
    g_autoptr(GTask) task = g_task_new(system, cancel, callback, data);
    int dir_copy = fcntl(dir_fd, F_DUPFD_CLOEXEC, 3);
    if (dir_copy < 0) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                                "AppImage の内容を開けません。元の配布ファイルを起動し直してください。");
        return;
    }
    g_autoptr(GTask) copy = g_task_new(system, cancel, helper_prepared, g_object_ref(task));
    g_task_set_task_data(copy, GINT_TO_POINTER(dir_copy), close_dir);
    g_task_run_in_thread(copy, copy_thread);
}

GDBusConnection *portable_connect_finish(GAsyncResult *result, GError **error)
{
    return g_task_propagate_pointer(G_TASK(result), error);
}
