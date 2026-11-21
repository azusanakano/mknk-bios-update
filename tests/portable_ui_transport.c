/* Exercise the real boundary without invoking pkexec or touching a host bus. */
#include "../src/portable.c"
#include <gio/gunixsocketaddress.h>
#include <glib/gstdio.h>

static void test_image(void)
{
    g_autofree char *root = g_dir_make_tmp("mknk-portable-XXXXXX", NULL);
    g_assert_nonnull(root);
    g_autofree char *usr = g_build_filename(root, "usr", NULL);
    g_autofree char *lib = g_build_filename(usr, "lib", NULL);
    g_autofree char *dir = g_build_filename(lib, "mknk-bios-update", NULL);
    g_autofree char *path = g_build_filename(dir, "portable-helper", NULL);
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(path, "first", 5, NULL));
    int fd = open(root, O_DIRECTORY | O_RDONLY);
    g_assert_cmpint(fd, >=, 3);
    g_autofree char *handle = g_strdup_printf("%d", fd);
    g_setenv("MKNK_BIOS_PORTABLE_DIR_FD", handle, TRUE);
    g_assert_cmpint(portable_take_appdir(), ==, fd);
    g_assert_cmpint(fcntl(fd, F_GETFD) & FD_CLOEXEC, !=, 0);
    g_autoptr(GError) error = NULL;
    int image = sealed_helper(fd, &error);
    g_assert_no_error(error);
    g_assert_cmpint(image, >=, 0);
    int seals = F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK;
    g_assert_cmpint(fcntl(image, F_GET_SEALS) & seals, ==, seals);
    g_assert_cmpint(fcntl(image, F_GETFD) & FD_CLOEXEC, !=, 0);
    g_assert_true(g_file_set_contents(path, "later", 5, NULL));
    char bytes[6] = {0};
    g_assert_cmpint(read(image, bytes, sizeof bytes), ==, 5);
    g_assert_cmpstr(bytes, ==, "first");
    g_assert_cmpint(pwrite(image, "x", 1, 0), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    close(image);
    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(symlink("/dev/null", path), ==, 0);
    g_assert_cmpint(sealed_helper(fd, &error), ==, -1);
    g_assert_nonnull(error);
    close(fd);
    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(g_rmdir(dir), ==, 0);
    g_assert_cmpint(g_rmdir(lib), ==, 0);
    g_assert_cmpint(g_rmdir(usr), ==, 0);
    g_assert_cmpint(g_rmdir(root), ==, 0);
}

static void test_addresses(void)
{
    g_assert_true(local_address("unix:abstract=mknk-bios"));
    g_assert_true(local_address("unix:path=/run/mknk-bios/socket,guid=0123456789abcdef0123456789abcdef"));
    const char *rejected[] = {"", "tcp:host=localhost", "unix:tmpdir=/run", "unix:path=/tmp/socket",
        "unix:path=/run/../tmp/socket", "unix:abstract=up;unix:path=/tmp/other", "unix:abstract=",
        "unix:abstract=a,abstract=b", "unix:path=/run/a,path=/run/b", "unix:abstract=a,extra=1",
        "unix:abstract=a,guid=invalid", "unix:abstract=%00"};
    for (guint i = 0; i < G_N_ELEMENTS(rejected); i++)
        g_assert_false(local_address(rejected[i]));
}

static gpointer local_server(gpointer data)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GSocketConnection) conn = g_socket_listener_accept(data, NULL, NULL, &error);
    g_assert_no_error(error);
    if (geteuid() != 0) {
        /* The GUI must reject this peer before sending even a D-Bus auth byte. */
        char byte;
        g_assert_cmpint(g_input_stream_read(g_io_stream_get_input_stream(G_IO_STREAM(conn)),
                                            &byte, 1, NULL, NULL), ==, 0);
        return NULL;
    }
    g_autofree char *guid = g_dbus_generate_guid();
    GDBusConnection *server = g_dbus_connection_new_sync(G_IO_STREAM(conn), guid,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_SERVER, NULL, NULL, &error);
    g_assert_no_error(error);
    return server;
}

static void test_credentials(void)
{
    g_autofree char *unique = g_dbus_generate_guid();
    g_autofree char *name = g_strconcat("mknk-test-", unique, NULL);
    g_autofree char *address = g_strconcat("unix:abstract=", name, NULL);
    g_autoptr(GSocketListener) listener = g_socket_listener_new();
    g_autoptr(GSocketAddress) socket = g_unix_socket_address_new_with_type(name, -1,
                                                                         G_UNIX_SOCKET_ADDRESS_ABSTRACT);
    g_autoptr(GError) error = NULL;
    g_assert_true(g_socket_listener_add_address(listener, socket, G_SOCKET_TYPE_STREAM,
                                                G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, &error));
    GThread *thread = g_thread_new("test-socket", local_server, listener);
    g_autoptr(GDBusConnection) peer = connect_root(address, NULL, &error);
    if (geteuid() == 0) {
        g_assert_no_error(error);
        g_assert_nonnull(peer);
        g_assert_null(g_dbus_connection_get_unique_name(peer));
    } else {
        g_assert_error(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED);
        g_assert_null(peer);
    }
    g_autoptr(GDBusConnection) server = g_thread_join(thread);
    if (server) g_dbus_connection_close_sync(server, NULL, NULL);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/portable/sealed-image", test_image);
    g_test_add_func("/portable/local-address", test_addresses);
    g_test_add_func("/portable/peer-credentials", test_credentials);
    return g_test_run();
}
