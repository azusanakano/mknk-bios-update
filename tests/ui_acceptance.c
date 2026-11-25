/* Native GTK controls, real GDBus serialization and FD passing, private bus.
 * No method in this test can reach the machine's system or session bus. */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

static void call_with_fds(GDBusConnection *connection, const char *bus_name, const char *path,
                          const char *interface, const char *method, GVariant *parameters,
                          const GVariantType *reply_type, GDBusCallFlags flags, gint timeout_msec,
                          GUnixFDList *fds, GCancellable *cancel, GAsyncReadyCallback callback,
                          gpointer data);

#define g_dbus_connection_call_with_unix_fd_list call_with_fds
#define main application_main
#define portable_connect_async mock_portable_connect_async
#include "../src/main.c"
#undef portable_connect_async
#undef main
#undef g_dbus_connection_call_with_unix_fd_list
#include <sys/mman.h>

static const char *mock_state = "idle", *mock_desktop = "gnome", *mock_power = "reboot";
static gboolean allowed = TRUE, withhold, hold_prepare, logout_block, ac = TRUE, fail_install;
static gboolean delay_authorize, hold_status, hold_authorize, hold_install, hold_recheck, result_this_boot;
static gboolean hold_candidates;
static gboolean hold_power, hold_power_reply;
static gboolean slow_query, takeover_view;
static guint rejections, takeovers;
static char *dismissed_plan;
static const char *install_error, *install_detail;
static const char *desktop_error, *mock_plan = "plan-1", *mock_recovery_detail = "";
enum { VALID_SHA512, CONFLICTING_DIGESTS, WRONG_REMOTE, WRONG_COMPONENT, VALID_BOTH };
static guint release_mode;
static gboolean can_replan_test, swapped_operation;
static const char *help_url = "", *recovery_url = "";
static guint checks_sent, prepares, permits, installs, reports, powers, desktop_calls;
static guint rechecks, cancelled, responses, stopped, declined;
static gboolean last_response;
static GDBusMethodInvocation *held_check, *held_prepare, *held_status, *held_authorize, *held_install, *held_recheck;
static GDBusMethodInvocation *held_power, *held_power_reply;
static GDBusMethodInvocation *held_candidates, *held_decline;
static GDBusConnection *service, *fwupd, *desktop;
static GDBusConnection *peer_service;
static GDBusServer *peer_server;
static guint helper_starts, status_calls;
static gboolean deny_helper;
static char *permit_sender, *client_sender, *reader;
static const char device_id[] = "0123456789012345678901234567890123456789";
#define DIGEST256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define HALF512 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DIGEST512 HALF512 HALF512
static const char mock_xml[] =
    "<node><interface name='" BIOS_BUS "'>"
    "<method name='Status'><arg type='s' direction='out'/></method>"
    "<method name='Check'><arg type='s' direction='out'/></method>"
    "<method name='Prepare'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='Dismiss'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='Replan'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='TakeOver'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='Authorize'><arg type='s' direction='in'/><arg type='s' direction='out'/>"
    "<arg type='s' direction='out'/><arg type='s' direction='out'/><arg type='h' direction='out'/></method>"
    "<method name='DeclineAuthorization'><arg type='s' direction='in'/></method>"
    "<method name='ReportRejection'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='Report'><arg type='s' direction='in'/><arg type='b' direction='in'/>"
    "<arg type='s' direction='out'/></method><method name='Power'><arg type='s' direction='in'/>"
    "<arg type='s' direction='out'/><arg type='s' direction='out'/><arg type='s' direction='out'/></method>"
    "<method name='RecheckPower'><arg type='s' direction='in'/></method>"
    "<method name='ReplyPower'><arg type='s' direction='in'/><arg type='b' direction='in'/></method>"
    "<signal name='Changed'/></interface>"
    "<interface name='" FWUPD "'><method name='GetUpgrades'><arg type='s' direction='in'/>"
    "<arg type='aa{sv}' direction='out'/></method><method name='Install'><arg type='s' direction='in'/>"
    "<arg type='h' direction='in'/><arg type='a{sv}' direction='in'/></method></interface>"
    "<interface name='org.freedesktop.login1.Manager'>"
    "<method name='GetSessionByPID'><arg type='u' direction='in'/><arg type='o' direction='out'/></method>"
    "<method name='CanReboot'><arg type='s' direction='out'/></method>"
    "<method name='CanPowerOff'><arg type='s' direction='out'/></method>"
    "<method name='ListInhibitors'><arg type='a(ssssuu)' direction='out'/></method></interface>"
    "<interface name='org.gnome.SessionManager'>"
    "<method name='RegisterClient'><arg type='s' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='o' direction='out'/></method><method name='UnregisterClient'><arg type='o' direction='in'/></method>"
    "<method name='IsInhibited'><arg type='u' direction='in'/><arg type='b' direction='out'/></method>"
    "<method name='Reboot'/><method name='RequestReboot'/><method name='Shutdown'/><method name='RequestShutdown'/></interface>"
    "<interface name='org.gnome.SessionManager.ClientPrivate'>"
    "<method name='EndSessionResponse'><arg type='b' direction='in'/><arg type='s' direction='in'/></method>"
    "<signal name='QueryEndSession'><arg type='u'/></signal><signal name='CancelEndSession'/>"
    "<signal name='EndSession'><arg type='u'/></signal><signal name='Stop'/></interface></node>";

static void return_view(GDBusMethodInvocation *inv, const char *s)
{
    const char *title = g_str_equal(s, "review") ? "更新内容を確認してください" :
                        g_str_equal(s, "available") ? "この機種に適用できる更新があります" :
                        g_str_equal(s, "pending") ? "再起動待ち" : "この PC の更新を確認";
    gboolean planless = g_str_equal(s, "idle") || g_str_equal(s, "available") ||
                        g_str_equal(s, "complete") || (g_str_equal(s, "hold") && result_this_boot);
    g_autofree char *text = g_strdup_printf(
        "{\"model\":\"検証用ノート NB-14\",\"current\":\"1.20\",\"state\":\"%s\",\"title\":\"%s\","
        "\"target\":\"1.24\",\"source\":\"LVFS 安定版\",\"scope\":\"システム BIOS\","
        "\"checked\":\"2026年11月21日 10時32分\",\"changes\":\"スリープ復帰時の画面表示を修正\","
        "\"plan\":\"%s\",\"token\":\"candidate-1\",\"power\":\"%s\",\"daemon_owner\":\"%s\",\"device\":\"%s\","
        "\"checksum\":\"" DIGEST256 "\",\"cab_sha512\":\"" DIGEST512 "\","
        "\"remote_id\":\"lvfs\",\"appstream_id\":\"com.example.Bios\",\"can_replan\":%s,"
        "\"support_url\":\"%s\",\"recovery_url\":\"%s\","
        "\"recovery_required\":true,\"recovery_detail\":\"%s\",\"can_check\":%s,\"can_prepare\":true,"
        "\"prepared_draft\":\"%s\",\"can_take_over\":%s,\"can_approve\":%s,\"can_power\":%s,\"result_this_boot\":%s}", s, title,
        planless ? "" : mock_plan,
        mock_power, g_dbus_connection_get_unique_name(fwupd), device_id,
        can_replan_test ? "true" : "false",
        help_url, recovery_url, mock_recovery_detail,
        g_str_equal(s, "pending") ? "false" : "true",
        g_str_equal(g_dbus_method_invocation_get_method_name(inv), "Prepare") ? "plan-1" : "",
        takeover_view ? "true" : "false", takeover_view ? "false" : "true",
        allowed ? "true" : "false", result_this_boot ? "true" : "false");
    g_dbus_method_invocation_return_value(inv, g_variant_new("(s)", text));
}

static void client_signal(const char *name, GVariant *args)
{
    g_assert_true(g_dbus_connection_emit_signal(desktop, client_sender, "/test/client",
                                                "org.gnome.SessionManager.ClientPrivate", name, args, NULL));
}

static void call_with_fds(GDBusConnection *connection, const char *bus_name, const char *path,
                          const char *interface, const char *method, GVariant *parameters,
                          const GVariantType *reply_type, GDBusCallFlags flags, gint timeout_msec,
                          GUnixFDList *fds, GCancellable *cancel, GAsyncReadyCallback callback,
                          gpointer data)
{
    /* Compress finite deadlines so the slow verification regression runs quickly. */
    if (delay_authorize && g_str_equal(method, "Authorize") && timeout_msec != G_MAXINT)
        timeout_msec = MAX(1, timeout_msec / 1000);
    g_dbus_connection_call_with_unix_fd_list(connection, bus_name, path, interface, method, parameters,
                                            reply_type, flags, timeout_msec, fds, cancel, callback, data);
}

static gboolean grant_authorization(gpointer data)
{
    GDBusMethodInvocation *inv = data;
    int fd = memfd_create("mock", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(write(fd, "simulated", 9), ==, 9);
    g_assert_cmpint(lseek(fd, 0, SEEK_SET), ==, 0);
    g_assert_cmpint(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL), ==, 0);
    g_autoptr(GUnixFDList) fds = g_unix_fd_list_new();
    g_assert_cmpint(g_unix_fd_list_append(fds, fd, NULL), ==, 0);
    close(fd);
    if (swapped_operation) mock_state = "uncertain";
    g_dbus_method_invocation_return_value_with_unix_fd_list(inv,
        g_variant_new("(sssh)", swapped_operation ? "other-plan" : "plan-1",
                      g_dbus_connection_get_unique_name(fwupd), device_id, 0), fds);
    return G_SOURCE_REMOVE;
}

static gboolean delayed_session_lookup(gpointer data)
{
    GDBusMethodInvocation *inv = data;
    gboolean session = g_str_equal(g_dbus_method_invocation_get_method_name(inv), "GetSessionByPID");
    g_dbus_method_invocation_return_value(inv, session ? g_variant_new("(o)", "/test/session")
                                                      : g_variant_new("(s)", "yes"));
    return G_SOURCE_REMOVE;
}

static void method_call(GDBusConnection *bus, const char *sender, const char *path,
                        const char *interface, const char *method, GVariant *args,
                        GDBusMethodInvocation *inv, gpointer data)
{
    (void) path; (void) data;
    GVariant *result = NULL;
    if (ui.portable && g_str_equal(interface, BIOS_BUS)) {
        g_assert_true(bus == peer_service);
        g_assert_null(sender);
        g_assert_null(g_dbus_message_get_destination(g_dbus_method_invocation_get_message(inv)));
    }
    if (g_str_equal(method, "Status")) {
        status_calls++;
        if (hold_status) {
            held_status = g_object_ref(inv);
            return;
        }
    } else if (g_str_equal(method, "Check")) {
        checks_sent++;
        if (withhold) {
            held_check = g_object_ref(inv);
            return;
        }
        mock_state = "available";
    } else if (g_str_equal(method, "Prepare")) {
        prepares++;
        mock_state = "review";
        if (hold_prepare) {
            held_prepare = g_object_ref(inv);
            return;
        }
    } else if (g_str_equal(method, "Dismiss")) {
        g_free(dismissed_plan);
        g_variant_get(args, "(s)", &dismissed_plan);
        mock_state = "idle";
    } else if (g_str_equal(method, "TakeOver")) {
        const char *plan;
        g_variant_get(args, "(&s)", &plan);
        g_assert_cmpstr(plan, ==, mock_plan);
        g_assert_true(g_dbus_message_get_flags(g_dbus_method_invocation_get_message(inv)) &
                      G_DBUS_MESSAGE_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION);
        takeovers++;
        takeover_view = FALSE;
        mock_state = "idle";
    } else if (g_str_equal(method, "Replan")) {
        g_assert_true(can_replan_test);
        can_replan_test = FALSE;
        mock_state = "idle";
    } else if (g_str_equal(method, "GetUpgrades")) {
        g_free(reader);
        reader = g_strdup(sender);
        GDBusMessage *msg = g_dbus_method_invocation_get_message(inv);
        g_assert_cmpstr(g_dbus_message_get_destination(msg), ==, g_dbus_connection_get_unique_name(fwupd));
        const char *selected;
        g_variant_get(args, "(&s)", &selected);
        g_assert_cmpstr(selected, ==, device_id);
        if (hold_candidates) {
            held_candidates = g_object_ref(inv);
            return;
        }
        GVariantBuilder entries, release;
        g_variant_builder_init(&entries, G_VARIANT_TYPE("aa{sv}"));
        g_variant_builder_init(&release, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_add(&release, "{sv}", "Version", g_variant_new_string("1.24"));
        g_variant_builder_add(&release, "{sv}", "RemoteId", g_variant_new_string(
            release_mode == WRONG_REMOTE ? "lvfs-testing" : "lvfs"));
        g_variant_builder_add(&release, "{sv}", "AppstreamId", g_variant_new_string(
            release_mode == WRONG_COMPONENT ? "com.example.Other" : "com.example.Bios"));
        const char *hashes = DIGEST512;
        if (release_mode == CONFLICTING_DIGESTS) hashes = DIGEST256 "," DIGEST256 DIGEST256;
        if (release_mode == VALID_BOTH) hashes = DIGEST256 "," DIGEST512;
        g_variant_builder_add(&release, "{sv}", "Checksum", g_variant_new_string(hashes));
        g_variant_builder_add_value(&entries, g_variant_builder_end(&release));
        result = g_variant_new("(aa{sv})", &entries);
    } else if (g_str_equal(method, "Authorize")) {
        permits++;
        g_assert_cmpstr(reader, ==, ui.portable ? g_dbus_connection_get_unique_name(ui.bus) : sender);
        g_free(permit_sender);
        permit_sender = g_strdup(reader);
        if (hold_authorize) {
            mock_state = "issuing";
            held_authorize = g_object_ref(inv);
        } else if (delay_authorize)
            g_timeout_add_full(G_PRIORITY_DEFAULT, 250, grant_authorization, g_object_ref(inv), g_object_unref);
        else grant_authorization(inv);
        return;
    } else if (g_str_equal(method, "DeclineAuthorization")) {
        const char *plan;
        g_variant_get(args, "(&s)", &plan);
        g_assert_cmpstr(plan, ==, "plan-1");
        g_assert_cmpstr(permit_sender, ==, ui.portable ? g_dbus_connection_get_unique_name(ui.bus) : sender);
        g_assert_cmpstr(mock_state, ==, "issuing");
        declined++;
        mock_state = "idle";
        held_decline = g_object_ref(inv);
        return;
    } else if (g_str_equal(method, "Install")) {
        installs++;
        g_assert_cmpstr(sender, ==, permit_sender);
        GDBusMessage *msg = g_dbus_method_invocation_get_message(inv);
        g_assert_cmpstr(g_dbus_message_get_destination(msg), ==, g_dbus_connection_get_unique_name(fwupd));
        g_assert_true(g_dbus_message_get_flags(msg) & G_DBUS_MESSAGE_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION);
        g_assert_true(g_dbus_message_get_flags(msg) & G_DBUS_MESSAGE_FLAGS_NO_AUTO_START);
        const char *device, *reason;
        gint handle;
        guint64 flags;
        g_autoptr(GVariant) opts = NULL;
        g_variant_get(args, "(&sh@a{sv})", &device, &handle, &opts);
        g_assert_cmpstr(device, ==, device_id);
        g_assert_true(valid_cab(g_dbus_message_get_unix_fd_list(msg), handle));
        g_assert_true(g_variant_lookup(opts, "reason", "&s", &reason));
        g_assert_cmpstr(reason, ==, "user-action");
        g_assert_true(g_variant_lookup(opts, "install-flags", "t", &flags));
        g_assert_cmpuint(flags, ==, 0);
        if (hold_install) {
            held_install = g_object_ref(inv);
            return;
        }
        if (install_error) {
            g_dbus_method_invocation_return_dbus_error(inv, install_error, install_detail);
            return;
        }
        if (fail_install) {
            g_dbus_method_invocation_return_dbus_error(inv, FWUPD ".Failed", "simulated after dispatch");
            return;
        }
        g_dbus_method_invocation_return_value(inv, NULL);
        return;
    } else if (g_str_equal(method, "ReportRejection")) {
        const char *op;
        g_variant_get(args, "(&s)", &op);
        g_assert_cmpstr(op, ==, "plan-1");
        rejections++;
        mock_state = "idle";
    } else if (g_str_equal(method, "Report")) {
        gboolean accepted;
        const char *op;
        g_variant_get(args, "(&sb)", &op, &accepted);
        g_assert_cmpstr(op, ==, "plan-1");
        g_assert_cmpint(accepted, ==, !fail_install && !install_error);
        reports++;
        mock_state = accepted ? "pending" : "uncertain";
    } else if (g_str_equal(method, "Power")) {
        powers++;
        if (hold_power) {
            held_power = g_object_ref(inv);
            return;
        }
        result = g_variant_new("(sss)", "request-1", mock_desktop, mock_power);
    } else if (g_str_equal(method, "RecheckPower")) {
        rechecks++;
        if (hold_recheck) {
            held_recheck = g_object_ref(inv);
            return;
        }
        if (!ac) {
            g_dbus_method_invocation_return_dbus_error(inv, BIOS_BUS ".Hold", "AC を接続してください。");
            return;
        }
    } else if (g_str_equal(method, "ReplyPower")) {
        const char *id;
        gboolean definitely_cancelled;
        g_variant_get(args, "(&sb)", &id, &definitely_cancelled);
        g_assert_cmpstr(id, ==, "request-1");
        if (definitely_cancelled) cancelled++;
        else stopped++;
        if (held_recheck) {
            /* The remote check may still finish after its caller cancels. */
            g_dbus_method_invocation_return_value(held_recheck, NULL);
            g_clear_object(&held_recheck);
        }
        if (hold_power_reply) {
            held_power_reply = g_object_ref(inv);
            return;
        }
    } else if (g_str_equal(method, "RegisterClient")) {
        g_free(client_sender);
        client_sender = g_strdup(sender);
        result = g_variant_new("(o)", "/test/client");
    } else if (slow_query && (g_str_equal(method, "GetSessionByPID") || g_str_equal(method, "CanReboot"))) {
        /* Three successful 3s calls put the last hardware check across the 10s query deadline. */
        g_timeout_add_full(G_PRIORITY_DEFAULT, 3000, delayed_session_lookup, g_object_ref(inv), g_object_unref);
        return;
    } else if (g_str_equal(method, "CanReboot") || g_str_equal(method, "CanPowerOff")) {
        g_assert_cmpstr(method, ==, g_str_equal(mock_power, "reboot") ? "CanReboot" : "CanPowerOff");
        result = g_variant_new("(s)", "yes");
    } else if (g_str_equal(method, "GetSessionByPID")) {
        result = g_variant_new("(o)", "/test/session");
    } else if (g_str_equal(method, "IsInhibited")) {
        result = g_variant_new("(b)", logout_block);
    } else if (g_str_equal(method, "ListInhibitors")) {
        GVariantBuilder locks;
        g_variant_builder_init(&locks, G_VARIANT_TYPE("a(ssssuu)"));
        result = g_variant_new("(a(ssssuu))", &locks);
    } else if (g_str_equal(method, "Reboot") || g_str_equal(method, "RequestReboot") ||
               g_str_equal(method, "Shutdown") || g_str_equal(method, "RequestShutdown")) {
        desktop_calls++;
        gboolean gnome = g_str_equal(mock_desktop, "gnome");
        const char *expected = g_str_equal(mock_power, "reboot") ? (gnome ? "Reboot" : "RequestReboot")
                                                                 : (gnome ? "Shutdown" : "RequestShutdown");
        g_assert_cmpstr(method, ==, expected);
        if (desktop_error) {
            g_dbus_method_invocation_return_dbus_error(inv, desktop_error, "simulated session manager error");
            return;
        }
    } else if (g_str_equal(method, "EndSessionResponse")) {
        const char *reason;
        g_variant_get(args, "(b&s)", &last_response, &reason);
        responses++;
    }
    if (g_str_equal(interface, BIOS_BUS) &&
        !g_str_equal(method, "Power") && !g_str_equal(method, "ReplyPower") && !g_str_equal(method, "RecheckPower")) {
        return_view(inv, mock_state);
        return;
    }
    g_dbus_method_invocation_return_value(inv, result);
}

static const GDBusInterfaceVTable vtable = { .method_call = method_call };

static void expose(GDBusConnection *bus, GDBusNodeInfo *node, const char *path, const char *iface)
{
    g_assert_cmpuint(g_dbus_connection_register_object(bus, path,
        g_dbus_node_info_lookup_interface(node, iface), &vtable, NULL, NULL, NULL), >, 0);
}

static gboolean accept_peer(GDBusServer *server, GDBusConnection *connection, gpointer data)
{
    (void) server;
    g_set_object(&peer_service, connection);
    expose(connection, data, BIOS_PATH, BIOS_BUS);
    return TRUE;
}

static void mock_peer_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source;
    g_autoptr(GTask) task = data;
    g_autoptr(GError) error = NULL;
    GDBusConnection *connection = g_dbus_connection_new_for_address_finish(result, &error);
    if (connection) g_task_return_pointer(task, connection, g_object_unref);
    else g_task_return_error(task, g_steal_pointer(&error));
}

/* Only this translation unit substitutes the interactive launch. All subsequent
 * calls, signals and file descriptors use a real GDBus peer and a separate bus. */
void mock_portable_connect_async(GDBusConnection *system, int dir_fd, GCancellable *cancel,
                                 GAsyncReadyCallback callback, gpointer data)
{
    (void) dir_fd;
    helper_starts++;
    g_assert_nonnull(g_dbus_connection_get_unique_name(system));
    GTask *task = g_task_new(system, cancel, callback, data);
    if (deny_helper) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, "管理者認証を取り消しました。");
        g_object_unref(task);
        return;
    }
    g_dbus_connection_new_for_address(g_dbus_server_get_client_address(peer_server),
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, cancel, mock_peer_ready, task);
}

static GDBusConnection *mock_connection(const char *address, const char *name)
{
    GDBusConnection *bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION |
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, NULL, NULL);
    g_assert_nonnull(bus);
    g_autoptr(GVariant) reply = g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", name, 4u), G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE, 1000, NULL, NULL);
    g_assert_nonnull(reply);
    return bus;
}

#define WAIT_WITHIN(expr, seconds) G_STMT_START { \
    gint64 until = g_get_monotonic_time() + (seconds) * G_TIME_SPAN_SECOND; \
    while (!(expr) && g_get_monotonic_time() < until) { \
        while (g_main_context_iteration(NULL, FALSE)) {} \
        g_usleep(1000); \
    } \
    g_assert_true(expr); \
} G_STMT_END
#define WAIT_FOR(expr) WAIT_WITHIN(expr, 6)

static GtkWidget *find_button(GtkWidget *root, const char *text)
{
    if (GTK_IS_BUTTON(root) && g_strcmp0(gtk_button_get_label(GTK_BUTTON(root)), text) == 0) return root;
    for (GtkWidget *w = gtk_widget_get_first_child(root); w; w = gtk_widget_get_next_sibling(w)) {
        GtkWidget *found = find_button(w, text);
        if (found) return found;
    }
    return NULL;
}

static GtkWidget *action_button(const char *text) { return find_button(ui.actions, text); }

static void click(const char *text)
{
    GtkWidget *w = action_button(text);
    g_assert_nonnull(w);
    g_assert_true(gtk_widget_is_sensitive(w));
    g_signal_emit_by_name(w, "clicked");
}

static void advance(const char *s)
{
    WAIT_FOR(state(s) && writable() && !ui.timer);
}

static void review_power(const char *action, const char *confirmation)
{
    guint service_calls = powers, session_calls = desktop_calls;
    click(action);
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_cmpuint(powers, ==, service_calls);
    g_assert_cmpuint(desktop_calls, ==, session_calls);
    g_assert_nonnull(action_button(confirmation));
    g_assert_nonnull(action_button("キャンセル"));
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("キャンセル"));
}

static void notify_change(const char *s)
{
    guint before = status_calls;
    g_assert_true(g_dbus_connection_emit_signal(ui.portable ? peer_service : service, NULL, BIOS_PATH,
                                               BIOS_BUS, "Changed", NULL, NULL));
    WAIT_FOR(status_calls > before);
    advance(s);
}

static void test_pending_focus(void)
{
    advance("pending");
    g_assert_true(gtk_widget_grab_focus(action_button("再起動する")));
    notify_change("pending");
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("再起動する"));

    GtkToggleButton *history = GTK_TOGGLE_BUTTON(find_button(GTK_WIDGET(ui.window), "履歴"));
    gtk_toggle_button_set_active(history, TRUE);
    notify_change("pending");
    g_assert_true(gtk_window_get_focus(ui.window) == ui.history_text);
    gtk_toggle_button_set_active(history, FALSE);

    review_power("再起動する", "再起動を続ける");
    g_assert_true(gtk_widget_grab_focus(action_button("再起動を続ける")));
    notify_change("pending");
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("再起動を続ける"));
    mock_plan = "replacement";
    notify_change("pending");
    g_assert_null(action_button("再起動を続ける"));
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("あとで"));
    g_assert_true(gtk_widget_grab_focus(action_button("再起動する")));
    mock_power = "shutdown";
    notify_change("pending");
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("あとで"));
}

static gboolean finish_recheck(gpointer data)
{
    (void) data;
    g_assert_nonnull(held_recheck);
    g_dbus_method_invocation_return_value(held_recheck, NULL);
    g_clear_object(&held_recheck);
    return G_SOURCE_REMOVE;
}

static void test_slow_power(gboolean late_query)
{
    advance("pending");
    hold_recheck = !late_query;
    review_power("再起動する", "再起動を続ける");
    click("再起動を続ける");
    if (!late_query) {
        WAIT_FOR(held_recheck);
        g_timeout_add(4500, finish_recheck, NULL);
        WAIT_FOR(desktop_calls || cancelled);
        g_assert_cmpuint(desktop_calls, ==, 1);
    } else {
        WAIT_FOR(desktop_calls == 1);
        hold_recheck = slow_query = TRUE;
        client_signal("QueryEndSession", g_variant_new("(u)", 0u));
        WAIT_WITHIN(held_recheck && responses == 1, 17);
        g_assert_false(last_response);
        finish_recheck(NULL);
        WAIT_FOR(responses == 2);
        g_assert_true(last_response);

        slow_query = FALSE;
        client_signal("QueryEndSession", g_variant_new("(u)", 0u));
        WAIT_FOR(held_recheck);
        g_autoptr(GDBusMethodInvocation) obsolete = g_steal_pointer(&held_recheck);
        client_signal("QueryEndSession", g_variant_new("(u)", 0u));
        WAIT_FOR(held_recheck);
        g_dbus_method_invocation_return_value(obsolete, NULL);
        g_dbus_method_invocation_return_dbus_error(held_recheck, BIOS_BUS ".Hold", "AC");
        g_clear_object(&held_recheck);
        WAIT_FOR(responses == 3);
        g_assert_false(last_response);
        client_signal("EndSession", g_variant_new("(u)", 0u));
        WAIT_FOR(responses == 4);
        g_assert_false(last_response);
    }
    client_signal("CancelEndSession", NULL);
    WAIT_FOR(cancelled == 1);
    advance("pending");
    if (late_query) {
        hold_recheck = FALSE;
        review_power("再起動する", "再起動を続ける");
        click("再起動を続ける");
        WAIT_FOR(desktop_calls == 2);
        hold_recheck = TRUE;
        client_signal("QueryEndSession", g_variant_new("(u)", 0u));
        WAIT_FOR(held_recheck);
        g_autoptr(GDBusMethodInvocation) abandoned = g_steal_pointer(&held_recheck);
        client_signal("CancelEndSession", NULL);
        WAIT_FOR(cancelled == 2);
        g_dbus_method_invocation_return_value(abandoned, NULL);
        advance("pending");
        g_assert_cmpuint(responses, ==, 4);
    }
}

static void test_abandon_own_draft(void)
{
    advance("available");
    hold_prepare = TRUE;
    click("更新する");
    WAIT_FOR(held_prepare);
    click("今回は見送る");
    mock_plan = "other-windows-approval";
    return_view(held_prepare, "review");
    g_clear_object(&held_prepare);
    advance("idle");
    g_assert_cmpstr(dismissed_plan, ==, "plan-1");
    g_assert_cmpuint(installs, ==, 0);
}

static void test_takeover(void)
{
    advance("review");
    g_assert_cmpuint(takeovers, ==, 0);
    g_assert_null(ui.approve);
    ui.read_only = TRUE;
    render();
    g_assert_null(action_button("管理者として承認を解除"));
    action_clicked(NULL, "TakeOver");
    ui.read_only = FALSE;
    render();
    click("管理者として承認を解除");
    advance("idle");
    g_assert_cmpuint(takeovers, ==, 1);
    g_assert_cmpuint(checks_sent, ==, 0);
    g_assert_cmpuint(permits, ==, 0);
    g_assert_cmpuint(installs, ==, 0);
    g_assert_nonnull(action_button("配布情報を再確認"));
}

static gboolean bus_has_name(const char *name)
{
    g_autoptr(GVariant) result = g_dbus_connection_call_sync(service, "org.freedesktop.DBus",
        "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", g_variant_new("(s)", name),
        G_VARIANT_TYPE("(b)"), G_DBUS_CALL_FLAGS_NONE, 1000, NULL, NULL);
    gboolean owned;
    g_assert_nonnull(result);
    g_variant_get(result, "(b)", &owned);
    return owned;
}

static void test_install_rejections(void)
{
    const struct { const char *name, *detail; gboolean rejected; } replies[] = {
        {FWUPD ".AuthFailed", "Failed to obtain auth", TRUE},
        {FWUPD ".AuthFailed", "different stage", FALSE},
        {"org.freedesktop.DBus.Error.ServiceUnknown", "daemon returned this name", FALSE},
        {"org.freedesktop.DBus.Error.NoReply", "no known outcome", FALSE},
        {NULL, NULL, TRUE},  /* Real bus routing error for a vanished unique name. */
    };
    for (guint i = 0; i < G_N_ELEMENTS(replies); i++) {
        mock_state = "available";
        if (i) click("状態を再確認");
        advance("available");
        click("更新する");
        advance("review");
        gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
        install_error = replies[i].name;
        install_detail = replies[i].detail;
        hold_authorize = !install_error;
        guint rejected_before = rejections, reports_before = reports, installs_before = installs;
        click("この更新を承認");
        if (hold_authorize) {
            WAIT_FOR(held_authorize);
            const char *owner = g_dbus_connection_get_unique_name(fwupd);
            g_assert_true(g_dbus_connection_close_sync(fwupd, NULL, NULL));
            WAIT_FOR(!bus_has_name(owner));
            grant_authorization(held_authorize);
            g_clear_object(&held_authorize);
        }
        WAIT_FOR(rejections > rejected_before || reports > reports_before);
        g_assert_cmpuint(rejections - rejected_before, ==, replies[i].rejected ? 1 : 0);
        g_assert_cmpuint(reports - reports_before, ==, replies[i].rejected ? 0 : 1);
        g_assert_cmpuint(installs - installs_before, ==, hold_authorize ? 0 : 1);
        advance(replies[i].rejected ? "idle" : "uncertain");
    }
}

static GtkExpander *details_expander(void)
{
    for (GtkWidget *w = gtk_widget_get_first_child(ui.page); w; w = gtk_widget_get_next_sibling(w)) {
        if (GTK_IS_EXPANDER(w)) return GTK_EXPANDER(w);
    }
    g_assert_not_reached();
}

static void test_review_refresh(void)
{
    gtk_expander_set_expanded(details_expander(), TRUE);
    g_assert_true(gtk_widget_grab_focus(GTK_WIDGET(details_expander())));
    notify_change("review");
    g_assert_true(gtk_expander_get_expanded(details_expander()));
    g_assert_true(gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.recovery)));
    g_assert_true(gtk_window_get_focus(ui.window) == GTK_WIDGET(details_expander()));
    g_assert_true(gtk_widget_grab_focus(ui.approve));
    notify_change("review");
    g_assert_true(gtk_window_get_focus(ui.window) == ui.approve);

    mock_recovery_detail = "新しい回復条件を確認してください。";
    notify_change("review");
    g_assert_false(gtk_expander_get_expanded(details_expander()));
    g_assert_false(gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.recovery)));
    g_assert_false(gtk_widget_is_sensitive(ui.approve));
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("今回は見送る"));

    gtk_expander_set_expanded(details_expander(), TRUE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    mock_plan = "replacement";
    notify_change("review");
    g_assert_false(gtk_expander_get_expanded(details_expander()));
    g_assert_false(gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.recovery)));
    mock_plan = "plan-1";
    mock_recovery_detail = "";
    notify_change("review");
}

static void test_desktop_replies(void)
{
    mock_desktop = "gnome";
    const char *rejections[] = {"org.gnome.SessionManager.LockedDown", "org.gnome.SessionManager.NotInRunning"};
    for (guint i = 0; i < G_N_ELEMENTS(rejections); i++) {
        guint before = cancelled;
        desktop_error = rejections[i];
        review_power("電源を切る", "電源を切る操作を続ける");
        click("電源を切る操作を続ける");
        WAIT_FOR(cancelled == before + 1);
        advance("pending");
    }
    guint before = cancelled, response_count = responses;
    desktop_error = "org.freedesktop.DBus.Error.NoReply";
    review_power("電源を切る", "電源を切る操作を続ける");
    click("電源を切る操作を続ける");
    WAIT_FOR(strstr(gtk_label_get_text(GTK_LABEL(ui.notice)), "受付結果が未確定") != NULL);
    g_assert_cmpuint(cancelled, ==, before);
    g_assert_true(ui.busy);
    client_signal("QueryEndSession", g_variant_new("(u)", 0u));
    WAIT_FOR(responses == response_count + 1);
    g_assert_true(last_response);
    client_signal("CancelEndSession", NULL);
    WAIT_FOR(cancelled == before + 1);
    advance("pending");
    desktop_error = NULL;
}

static void test_portable_close(const char *operation)
{
    advance("available");
    if (g_str_equal(operation, "status")) {
        hold_status = TRUE;
        click("状態を再確認");
        WAIT_FOR(held_status);
    } else if (g_str_equal(operation, "check")) {
        withhold = TRUE;
        click("配布情報を再確認");
        WAIT_FOR(held_check);
    } else if (g_str_equal(operation, "prepare")) {
        hold_prepare = TRUE;
        click("更新する");
        WAIT_FOR(held_prepare);
    } else if (g_str_equal(operation, "power") || g_str_equal(operation, "power-request")) {
        mock_state = "pending";
        click("状態を再確認");
        advance("pending");
        hold_power = g_str_equal(operation, "power-request");
        hold_recheck = !hold_power;
        hold_power_reply = TRUE;
        review_power("再起動する", "再起動を続ける");
        click("再起動を続ける");
        WAIT_FOR(held_recheck || held_power);
    } else {
        click("更新する");
        advance("review");
        gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
        if (g_str_equal(operation, "candidates")) hold_candidates = TRUE;
        else if (g_str_equal(operation, "authorize")) hold_authorize = TRUE;
        else {
            g_assert_cmpstr(operation, ==, "install");
            hold_install = TRUE;
        }
        click("この更新を承認");
        WAIT_FOR(held_candidates || held_authorize || held_install);
    }
    gint64 closed_at = g_get_monotonic_time();
    gtk_window_close(ui.window);
    if (held_power) {
        g_assert_false(g_dbus_connection_is_closed(peer_service));
        g_dbus_method_invocation_return_value(held_power, g_variant_new("(sss)", "request-1", mock_desktop, mock_power));
        g_clear_object(&held_power);
    }
    if (hold_power_reply) {
        WAIT_FOR(held_power_reply);
        g_assert_false(g_dbus_connection_is_closed(peer_service));
        g_dbus_method_invocation_return_value(held_power_reply, NULL);
        g_clear_object(&held_power_reply);
    }
    if (held_authorize) {
        g_assert_nonnull(ui.control);
        g_assert_false(g_dbus_connection_is_closed(peer_service));
        grant_authorization(held_authorize);
        g_clear_object(&held_authorize);
        WAIT_FOR(held_decline);
        g_assert_false(g_dbus_connection_is_closed(peer_service));
        g_dbus_method_invocation_return_value(held_decline, NULL);
        g_clear_object(&held_decline);
    }
    if (hold_install) {
        g_assert_false(g_dbus_connection_is_closed(peer_service));
        fail_install = TRUE;
        g_dbus_method_invocation_return_dbus_error(held_install, "org.freedesktop.DBus.Error.NoReply",
                                                    "simulated reply lost after dispatch");
        g_clear_object(&held_install);
    }
    WAIT_FOR(g_dbus_connection_is_closed(peer_service));
    g_assert_true(g_get_monotonic_time() - closed_at < 2 * G_TIME_SPAN_SECOND);
    g_assert_cmpuint(cancelled, ==, hold_power_reply ? 1 : 0);
    g_assert_cmpuint(rechecks, ==, hold_recheck ? 1 : 0);
    g_assert_cmpuint(desktop_calls, ==, 0);
    g_assert_cmpuint(permits, ==, hold_authorize || hold_install ? 1 : 0);
    g_assert_cmpuint(declined, ==, hold_authorize ? 1 : 0);
    g_assert_cmpuint(installs, ==, hold_install ? 1 : 0);
    g_assert_cmpuint(reports, ==, hold_install ? 1 : 0);
}

static void painted(GdkFrameClock *clock, gpointer data)
{
    (void) clock;
    *(gboolean *) data = TRUE;
}

static void preview(void)
{
    const char *output = g_getenv("MKNK_UI_PREVIEW");
    if (!output || !*output) return;
    g_object_set(gtk_settings_get_default(), "gtk-font-name", "Sans 11", NULL);
    gtk_window_set_default_size(ui.window, 680, 780);
    GtkWidget *window = GTK_WIDGET(ui.window);
    GdkFrameClock *clock = gtk_widget_get_frame_clock(window);
    gboolean visible_frame = FALSE;
    gulong handler = g_signal_connect(clock, "after-paint", G_CALLBACK(painted), &visible_frame);
    gtk_widget_queue_draw(window);
    WAIT_FOR(visible_frame);
    g_signal_handler_disconnect(clock, handler);
    int width = gtk_widget_get_width(window), height = gtk_widget_get_height(window);
    g_autoptr(GdkPaintable) paintable = gtk_widget_paintable_new(window);
    GtkSnapshot *snapshot = gtk_snapshot_new();
    gdk_paintable_snapshot(paintable, GDK_SNAPSHOT(snapshot), width, height);
    g_autoptr(GskRenderNode) node = gtk_snapshot_free_to_node(snapshot);
    g_assert_nonnull(node);
    graphene_rect_t area = GRAPHENE_RECT_INIT(0, 0, width, height);
    GskRenderer *renderer = gtk_native_get_renderer(GTK_NATIVE(window));
    g_autoptr(GdkTexture) image = gsk_renderer_render_texture(renderer, node, &area);
    g_assert_true(gdk_texture_save_to_png(image, output));
    g_object_set(gtk_settings_get_default(), "gtk-font-name", "Sans 22", NULL);
}

int main(int argc, char **argv)
{
    gboolean status_start = argc == 2 && g_str_equal(argv[1], "--test-status-start");
    gboolean pending_start = argc == 2 && g_str_equal(argv[1], "--test-pending-start");
    gboolean login_start = argc == 2 && g_str_has_prefix(argv[1], "--test-login-");
    gboolean portable = argc == 2 && g_str_has_prefix(argv[1], "--test-portable-");
    gboolean portable_status = portable && g_str_equal(argv[1], "--test-portable-status");
    const char *native = argc == 2 && g_str_has_prefix(argv[1], "--test-native-")
                       ? argv[1] + strlen("--test-native-") : "";
    gboolean historical = argc == 2 && g_str_has_suffix(argv[1], "-historical");
    gboolean recent = argc == 2 && g_str_has_suffix(argv[1], "-this-boot");
    gboolean bus_restart = g_str_equal(native, "bus-restart");
    const char *close_prefix = "--test-portable-close-";
    const char *close_operation = portable && g_str_has_prefix(argv[1], close_prefix) ? argv[1] + strlen(close_prefix) : NULL;
    if (login_start) {
        if (g_str_equal(argv[1], "--test-login-installed") || g_str_equal(argv[1], "--test-login-old-result"))
            mock_state = "complete";
        if (g_str_equal(argv[1], "--test-login-unapplied")) mock_state = "hold";
        result_this_boot = g_str_equal(argv[1], "--test-login-installed") || g_str_equal(argv[1], "--test-login-unapplied");
    }
    if (historical || recent) {
        mock_state = "complete";
        result_this_boot = recent;
    } else if (*native) {
        takeover_view = g_str_equal(native, "takeover");
        mock_state = takeover_view ? "review" :
                     g_str_equal(native, "install-rejections") || g_str_equal(native, "abandon-draft")
                     ? "available" : "pending";
    }
    if (status_start || pending_start || login_start || portable || *native) {
        argc = 1;
        argv[1] = NULL;
    }
    g_test_init(&argc, &argv, NULL);
    if (!status_start && !pending_start && !login_start && !portable && !*native) {
        char *modes[] = {"--test-status-start", "--test-pending-start", "--test-login-start",
                         "--test-login-installed", "--test-login-unapplied", "--test-login-old-result",
                         "--test-portable-status", "--test-portable-plan", "--test-portable-close-status",
                         "--test-portable-close-check", "--test-portable-close-prepare", "--test-portable-close-power",
                         "--test-portable-close-power-request", "--test-portable-close-candidates",
                         "--test-portable-close-authorize", "--test-portable-close-install",
                         "--test-native-slow-preflight", "--test-native-late-query", "--test-native-bus-restart",
                         "--test-native-pending-focus", "--test-native-historical", "--test-native-readonly-historical",
                         "--test-native-this-boot", "--test-portable-historical", "--test-portable-this-boot",
                         "--test-native-abandon-draft", "--test-native-install-rejections", "--test-native-takeover"};
        for (guint i = 0; i < G_N_ELEMENTS(modes); i++) {
            char *child[] = {argv[0], modes[i], NULL};
            int result;
            g_assert_true(g_spawn_sync(NULL, child, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL, &result, NULL));
            g_assert_true(g_spawn_check_wait_status(result, NULL));
        }
    }
    g_autofree char *display = g_strdup(g_getenv("DISPLAY"));
    GTestDBus *first_system = NULL;
    if (bus_restart) {
        first_system = g_test_dbus_new(G_TEST_DBUS_NONE);
        g_test_dbus_up(first_system);
    }
    GTestDBus *sandbox = g_test_dbus_new(G_TEST_DBUS_NONE);
    g_test_dbus_up(sandbox);
    if (display) g_setenv("DISPLAY", display, TRUE);
    const char *address = g_test_dbus_get_bus_address(sandbox);
    const char *system_address = first_system ? g_test_dbus_get_bus_address(first_system) : address;
    g_autofree char *routes = first_system ? g_strjoin(";", system_address, address, NULL) : g_strdup(address);
    g_setenv("DBUS_SYSTEM_BUS_ADDRESS", routes, TRUE);
    g_setenv("GTK_A11Y", "none", TRUE);
    g_setenv("GSETTINGS_BACKEND", "memory", TRUE);
    service = mock_connection(system_address, BIOS_BUS);
    fwupd = mock_connection(system_address, FWUPD);
    desktop = mock_connection(address, "org.gnome.SessionManager");
    GDBusConnection *login = mock_connection(system_address, "org.freedesktop.login1");
    g_autoptr(GDBusNodeInfo) node = g_dbus_node_info_new_for_xml(mock_xml, NULL);
    expose(service, node, BIOS_PATH, BIOS_BUS);
    expose(fwupd, node, "/", FWUPD);
    expose(login, node, "/org/freedesktop/login1", "org.freedesktop.login1.Manager");
    expose(desktop, node, "/org/gnome/SessionManager", "org.gnome.SessionManager");
    expose(desktop, node, "/test/client", "org.gnome.SessionManager.ClientPrivate");
    if (portable) {
        g_autofree char *guid = g_dbus_generate_guid();
        peer_server = g_dbus_server_new_sync("unix:tmpdir=/tmp", G_DBUS_SERVER_FLAGS_NONE, guid,
                                             NULL, NULL, NULL);
        g_assert_nonnull(peer_server);
        g_signal_connect(peer_server, "new-connection", G_CALLBACK(accept_peer), node);
        g_dbus_server_start(peer_server);
    }
    ui.app = gtk_application_new(BIOS_APP, G_APPLICATION_NON_UNIQUE);
    g_assert_true(g_application_register(G_APPLICATION(ui.app), NULL, NULL));
    g_object_set(gtk_settings_get_default(), "gtk-font-name", "Sans 22", NULL);
    ui.login = login_start;
    ui.portable = portable;
    ui.read_only = status_start || login_start || portable_status || g_str_equal(native, "readonly-historical");
    if (pending_start) mock_state = "pending";
    activate(ui.app, NULL);
    if (portable) {
        click("状態を再確認");
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_assert_null(ui.bus);
        g_assert_null(ui.control);
        g_assert_cmpuint(helper_starts, ==, 0);
        g_assert_cmpuint(status_calls, ==, 0);
        g_assert_cmpuint(checks_sent, ==, 0);
        g_autofree char *model = dmi("product_name");
        g_autofree char *version = dmi("bios_version");
        g_autofree char *current = g_strconcat("現在の BIOS　", version, NULL);
        g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(ui.model)), ==, model);
        g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(ui.current)), ==, current);
        if (portable_status) {
            g_assert_null(action_button("更新情報を確認"));
            g_assert_nonnull(action_button("通常モードで開き直す"));
            action_clicked(NULL, "OpenPortable");
            g_assert_false(ui.opening);
            g_test_dbus_stop(sandbox);
            return 0;
        }
        deny_helper = TRUE;
        click("更新情報を確認");
        action_clicked(NULL, "OpenPortable");
        WAIT_FOR(!ui.opening);
        g_assert_cmpuint(helper_starts, ==, 1);
        g_assert_cmpuint(checks_sent, ==, 0);
        g_assert_null(ui.control);
        g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(ui.current)), ==, current);
        g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(ui.notice)), "管理者認証"));
        deny_helper = FALSE;
        click("更新情報を確認");
        action_clicked(NULL, "OpenPortable");
        WAIT_FOR(ui.control != NULL);
        g_assert_cmpuint(helper_starts, ==, 2);
        g_assert_true(ui.control != ui.bus);
        g_assert_null(ui.owner);
        if (close_operation) {
            test_portable_close(close_operation);
            g_test_dbus_stop(sandbox);
            return 0;
        }
    }
    if (historical || recent || *native) {
        if (historical || recent) {
            if (historical && !ui.read_only) {
                WAIT_FOR(ui.fresh && !ui.busy && !ui.reading && !ui.first_status);
                g_assert_cmpuint(checks_sent, ==, 1);
                g_assert_true(state("available"));
            } else {
                WAIT_FOR(ui.fresh && !ui.reading);
                g_assert_true(state("complete"));
                g_assert_cmpuint(checks_sent, ==, 0);
            }
        } else if (bus_restart) {
            advance("pending");
            /* Another subsystem can keep a reference to the shared bus for its entire lifetime. */
            g_autoptr(GDBusConnection) old = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
            g_dbus_connection_set_exit_on_close(old, FALSE);
            g_test_dbus_stop(first_system);
            WAIT_FOR(g_dbus_connection_is_closed(old) && !ui.control);
            service = mock_connection(address, BIOS_BUS);
            expose(service, node, BIOS_PATH, BIOS_BUS);
            mock_state = "available";
            click("状態を再確認");
            advance("available");
            g_assert_false(g_dbus_connection_is_closed(ui.bus));
        } else if (g_str_equal(native, "pending-focus")) test_pending_focus();
        else if (g_str_equal(native, "slow-preflight")) test_slow_power(FALSE);
        else if (g_str_equal(native, "late-query")) test_slow_power(TRUE);
        else if (g_str_equal(native, "abandon-draft")) test_abandon_own_draft();
        else if (g_str_equal(native, "install-rejections")) test_install_rejections();
        else if (g_str_equal(native, "takeover")) test_takeover();
        else g_assert_not_reached();
        g_test_dbus_stop(sandbox);
        return 0;
    }
    if (status_start || pending_start || login_start) {
        WAIT_FOR(ui.fresh && !ui.busy && !ui.reading);
        g_assert_cmpuint(checks_sent, ==, 0);
        g_assert_cmpuint(installs, ==, 0);
        g_assert_cmpuint(powers, ==, 0);
        g_assert_nonnull(action_button("状態を再確認"));
        if (pending_start) g_assert_true(state("pending"));
        if (status_start || login_start) g_assert_null(action_button("配布情報を再確認"));
        if (login_start) g_assert_true(state(mock_state));
        g_assert_cmpint(gtk_widget_get_visible(GTK_WIDGET(ui.window)), ==, !login_start || result_this_boot);
        g_test_dbus_stop(sandbox);
        return 0;
    }
    advance("available");
    g_assert_cmpuint(checks_sent, ==, 1);
    click("更新する");
    advance("review");
    if (!portable) preview();
    g_assert_null(gtk_widget_get_ancestor(ui.actions, GTK_TYPE_SCROLLED_WINDOW));
    g_assert_null(gtk_widget_get_ancestor(ui.model, GTK_TYPE_SCROLLED_WINDOW));
    g_assert_nonnull(gtk_widget_get_ancestor(ui.page, GTK_TYPE_SCROLLED_WINDOW));
    g_assert_nonnull(gtk_widget_get_ancestor(ui.history, GTK_TYPE_SCROLLED_WINDOW));
    int compact_height, wide_height;
    gtk_widget_measure(ui.actions, GTK_ORIENTATION_VERTICAL, 260, NULL, &compact_height, NULL, NULL);
    gtk_widget_measure(ui.actions, GTK_ORIENTATION_VERTICAL, 1200, NULL, &wide_height, NULL, NULL);
    g_assert_cmpint(compact_height, >, wide_height);
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("今回は見送る"));
    g_assert_false(gtk_widget_is_sensitive(ui.approve));
    g_assert_true(gtk_widget_child_focus(ui.actions, GTK_DIR_TAB_FORWARD));
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("状態を再確認"));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    g_assert_true(gtk_widget_child_focus(ui.actions, GTK_DIR_TAB_BACKWARD));
    g_assert_true(gtk_window_get_focus(ui.window) == ui.approve);
    test_review_refresh();
    click("今回は見送る");
    advance("idle");
    g_assert_cmpuint(installs, ==, 0);
    click("配布情報を再確認");
    advance("available");
    click("更新する");
    advance("review");
    g_assert_false(gtk_widget_is_sensitive(ui.approve));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    delay_authorize = TRUE;
    click("この更新を承認");
    action_clicked(NULL, "Authorize"); /* another activation in the same event loop turn */
    WAIT_FOR(permits == 1);
    g_assert_cmpuint(installs, ==, 0);
    advance("pending");
    delay_authorize = FALSE;
    g_assert_cmpuint(permits, ==, 1);
    g_assert_cmpuint(installs, ==, 1);
    g_assert_cmpuint(reports, ==, 1);
    g_assert_true(gtk_window_get_focus(ui.window) == action_button("あとで"));
    click("あとで");
    g_assert_cmpuint(powers, ==, 0);
    allowed = FALSE;
    click("起動操作を表示");
    advance("pending");
    g_assert_null(action_button("再起動する"));
    allowed = TRUE;
    click("状態を再確認");
    advance("pending");
    review_power("再起動する", "再起動を続ける");
    mock_power = "shutdown";
    notify_change("pending");
    g_assert_null(action_button("再起動を続ける"));
    g_assert_cmpuint(powers, ==, 0);
    mock_power = "reboot";
    notify_change("pending");
    logout_block = TRUE;
    review_power("再起動する", "再起動を続ける");
    click("再起動を続ける");
    WAIT_FOR(cancelled == 1);
    advance("pending");
    g_assert_cmpuint(desktop_calls, ==, 0);
    logout_block = FALSE;
    for (guint i = 0; i < 2; i++) {
        mock_desktop = i ? "cinnamon" : "gnome";
        guint service_calls = powers, session_calls = desktop_calls;
        review_power("再起動する", "再起動を続ける");
        click("キャンセル");
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_assert_cmpuint(powers, ==, service_calls);
        g_assert_cmpuint(desktop_calls, ==, session_calls);
        review_power("再起動する", "再起動を続ける");
        click("再起動を続ける");
        WAIT_FOR(desktop_calls == i + 1);
        ac = i != 0;
        client_signal("QueryEndSession", g_variant_new("(u)", 0u));
        WAIT_FOR(responses == i + 1);
        g_assert_cmpint(last_response, ==, ac);
        client_signal("CancelEndSession", NULL);
        WAIT_FOR(cancelled == i + 2);
        advance("pending");
        ac = TRUE;
    }
    g_assert_cmpuint(rechecks, ==, 4);
    mock_power = "shutdown";
    click("状態を再確認");
    advance("pending");
    g_assert_null(action_button("再起動する"));
    review_power("電源を切る", "電源を切る操作を続ける");
    click("電源を切る操作を続ける");
    WAIT_FOR(desktop_calls == 3);
    client_signal("QueryEndSession", g_variant_new("(u)", 0u));
    WAIT_FOR(responses == 3);
    g_assert_true(last_response);
    client_signal("EndSession", g_variant_new("(u)", 0u));
    WAIT_FOR(responses == 4);
    g_assert_true(last_response);
    client_signal("Stop", NULL);
    WAIT_FOR(stopped == 1);
    advance("pending");
    test_desktop_replies();
    mock_power = "reboot";
    g_assert_cmpuint(installs, ==, 1);
    mock_state = "idle";
    click("状態を再確認");
    advance("idle");
    withhold = TRUE;
    click("配布情報を再確認");
    WAIT_FOR(held_check != NULL);
    mock_state = "pending";
    g_assert_true(g_dbus_connection_emit_signal(portable ? peer_service : service, NULL, BIOS_PATH,
                                               BIOS_BUS, "Changed", NULL, NULL));
    WAIT_FOR(state("pending") && ui.busy);
    return_view(held_check, "available");
    g_clear_object(&held_check);
    advance("pending");
    g_assert_null(action_button("更新する"));
    g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(ui.current)), ==, "現在の BIOS　1.20");
    ui.read_only = TRUE;
    render();
    g_assert_null(action_button("再起動する"));
    g_assert_null(action_button("配布情報を再確認"));
    g_assert_nonnull(action_button("状態を再確認"));
    g_assert_cmpuint(prepares, ==, 2);
    ui.read_only = FALSE;
    withhold = FALSE;
    mock_state = "idle";
    click("状態を再確認");
    advance("idle");
    click("配布情報を再確認");
    advance("available");
    hold_prepare = TRUE;
    click("更新する");
    WAIT_FOR(held_prepare != NULL);
    click("今回は見送る");
    return_view(held_prepare, "review");
    g_clear_object(&held_prepare);
    advance("idle");
    g_assert_cmpuint(installs, ==, 1);
    hold_prepare = FALSE;
    fail_install = TRUE;
    click("配布情報を再確認");
    advance("available");
    click("更新する");
    advance("review");
    for (release_mode = CONFLICTING_DIGESTS; release_mode <= WRONG_COMPONENT; release_mode++) {
        gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
        click("この更新を承認");
        advance("review");
        g_assert_cmpuint(permits, ==, 1);
        g_assert_cmpuint(installs, ==, 1);
    }
    release_mode = VALID_BOTH;
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    click("この更新を承認");
    advance("uncertain");
    g_assert_null(action_button("この更新を承認"));
    click("状態を再確認");
    advance("uncertain");
    g_assert_cmpuint(installs, ==, 2);
    g_assert_cmpuint(reports, ==, 2);
    g_assert_null(action_button("更新計画を作り直す"));
    can_replan_test = TRUE;
    click("状態を再確認");
    advance("uncertain");
    click("更新計画を作り直す");
    advance("idle");
    g_assert_cmpuint(installs, ==, 2);
    swapped_operation = TRUE;
    click("配布情報を再確認");
    advance("available");
    click("更新する");
    advance("review");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    click("この更新を承認");
    advance("uncertain");
    g_assert_cmpuint(installs, ==, 2);
    g_assert_cmpuint(reports, ==, 2);
    mock_state = "hold";
    click("状態を再確認");
    advance("hold");
    g_assert_null(find_button(ui.page, "メーカーの更新手順"));
    g_assert_null(find_button(ui.page, "メーカーの復旧手順"));
    help_url = "https://support.example.invalid/nb14/updates";
    recovery_url = "https://support.example.invalid/nb14/recovery";
    click("状態を再確認");
    advance("hold");
    GtkWidget *guide = find_button(ui.page, "メーカーの更新手順"), *recovery = find_button(ui.page, "メーカーの復旧手順");
    g_assert_true(GTK_IS_LINK_BUTTON(guide));
    g_assert_true(GTK_IS_LINK_BUTTON(recovery));
    g_assert_cmpstr(gtk_link_button_get_uri(GTK_LINK_BUTTON(guide)), ==, help_url);
    g_assert_cmpstr(gtk_link_button_get_uri(GTK_LINK_BUTTON(recovery)), ==, recovery_url);
    help_url = "file:///tmp/ignored";
    recovery_url = "";
    click("状態を再確認");
    advance("hold");
    g_assert_null(find_button(ui.page, "メーカーの更新手順"));
    g_assert_null(find_button(ui.page, "メーカーの復旧手順"));
    if (portable) {
        /* A replacement helper must come from a new explicit click. */
        g_assert_true(g_dbus_connection_close_sync(peer_service, NULL, NULL));
        WAIT_FOR(!ui.control && !ui.fresh);
        click("状態を再確認");
        g_assert_cmpuint(helper_starts, ==, 2);
        click("更新情報を確認");
        advance("hold");
        g_assert_cmpuint(helper_starts, ==, 3);
        g_assert_cmpuint(installs, ==, 2);
        g_test_dbus_stop(sandbox);
        return 0;
    }
    g_autoptr(GVariant) lost = g_dbus_connection_call_sync(service, "org.freedesktop.DBus",
        "/org/freedesktop/DBus", "org.freedesktop.DBus", "ReleaseName", g_variant_new("(s)", BIOS_BUS),
        G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 1000, NULL, NULL);
    g_assert_nonnull(lost);
    WAIT_FOR(!ui.owner && !ui.fresh);
    g_assert_cmpuint(installs, ==, 2);
    g_assert_nonnull(action_button("状態を再確認"));
    g_assert_null(action_button("配布情報を再確認"));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(ui.current)), "現在の BIOS"));
    g_test_dbus_stop(sandbox);
    return 0;
}
