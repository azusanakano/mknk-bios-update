/* Native GTK controls, real GDBus serialization and FD passing, private bus.
 * No method in this test can reach the machine's system or session bus. */
#define main application_main
#include "../src/main.c"
#undef main
#include <sys/mman.h>

static const char *mock_state = "idle", *mock_desktop = "gnome", *mock_power = "reboot";
static gboolean allowed = TRUE, withhold, hold_prepare, logout_block, ac = TRUE, fail_install;
enum { VALID_SHA512, CONFLICTING_DIGESTS, WRONG_REMOTE, WRONG_COMPONENT, VALID_BOTH };
static guint release_mode;
static gboolean can_replan_test, swapped_operation;
static const char *help_url = "", *recovery_url = "";
static guint checks_sent, prepares, permits, installs, reports, powers, desktop_calls;
static guint rechecks, cancelled, responses, stopped;
static gboolean last_response;
static GDBusMethodInvocation *held_check, *held_prepare;
static GDBusConnection *service, *fwupd, *desktop;
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
    "<method name='Authorize'><arg type='s' direction='in'/><arg type='s' direction='out'/>"
    "<arg type='s' direction='out'/><arg type='s' direction='out'/><arg type='h' direction='out'/></method>"
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
    g_autofree char *text = g_strdup_printf(
        "{\"model\":\"検証用ノート NB-14\",\"current\":\"1.20\",\"state\":\"%s\",\"title\":\"%s\","
        "\"target\":\"1.24\",\"source\":\"LVFS 安定版\",\"scope\":\"システム BIOS\","
        "\"checked\":\"2026年11月21日 10時32分\",\"changes\":\"スリープ復帰時の画面表示を修正\","
        "\"plan\":\"%s\",\"token\":\"candidate-1\",\"power\":\"%s\",\"daemon_owner\":\"%s\",\"device\":\"%s\","
        "\"checksum\":\"" DIGEST256 "\",\"cab_sha512\":\"" DIGEST512 "\","
        "\"remote_id\":\"lvfs\",\"appstream_id\":\"com.example.Bios\",\"can_replan\":%s,"
        "\"support_url\":\"%s\",\"recovery_url\":\"%s\","
        "\"recovery_required\":true,\"can_check\":%s,\"can_prepare\":true,"
        "\"can_approve\":true,\"can_power\":%s}", s, title,
        (g_str_equal(s, "idle") || g_str_equal(s, "available")) ? "" : "plan-1",
        mock_power, g_dbus_connection_get_unique_name(fwupd), device_id,
        can_replan_test ? "true" : "false",
        help_url, recovery_url,
        g_str_equal(s, "pending") ? "false" : "true",
        allowed ? "true" : "false");
    g_dbus_method_invocation_return_value(inv, g_variant_new("(s)", text));
}

static void client_signal(const char *name, GVariant *args)
{
    g_assert_true(g_dbus_connection_emit_signal(desktop, client_sender, "/test/client",
                                                "org.gnome.SessionManager.ClientPrivate", name, args, NULL));
}

static void method_call(GDBusConnection *bus, const char *sender, const char *path,
                        const char *interface, const char *method, GVariant *args,
                        GDBusMethodInvocation *inv, gpointer data)
{
    (void) bus; (void) path; (void) interface; (void) data;
    GVariant *result = NULL;
    if (g_str_equal(method, "Check")) {
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
        g_assert_cmpstr(reader, ==, sender);
        g_free(permit_sender);
        permit_sender = g_strdup(sender);
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
        if (fail_install) {
            g_dbus_method_invocation_return_dbus_error(inv, FWUPD ".Failed", "simulated after dispatch");
            return;
        }
        g_dbus_method_invocation_return_value(inv, NULL);
        return;
    } else if (g_str_equal(method, "Report")) {
        gboolean accepted;
        const char *op;
        g_variant_get(args, "(&sb)", &op, &accepted);
        g_assert_cmpstr(op, ==, "plan-1");
        g_assert_cmpint(accepted, ==, !fail_install);
        reports++;
        mock_state = accepted ? "pending" : "uncertain";
    } else if (g_str_equal(method, "Power")) {
        powers++;
        result = g_variant_new("(sss)", "request-1", mock_desktop, mock_power);
    } else if (g_str_equal(method, "RecheckPower")) {
        rechecks++;
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
    } else if (g_str_equal(method, "RegisterClient")) {
        g_free(client_sender);
        client_sender = g_strdup(sender);
        result = g_variant_new("(o)", "/test/client");
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

#define WAIT_FOR(expr) G_STMT_START { \
    gint64 until = g_get_monotonic_time() + 6 * G_TIME_SPAN_SECOND; \
    while (!(expr) && g_get_monotonic_time() < until) { \
        while (g_main_context_iteration(NULL, FALSE)) {} \
        g_usleep(1000); \
    } \
    g_assert_true(expr); \
} G_STMT_END

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
    gboolean silent_start = argc == 2 && g_str_equal(argv[1], "--test-login-start");
    if (status_start || pending_start || silent_start) {
        argc = 1;
        argv[1] = NULL;
    }
    g_test_init(&argc, &argv, NULL);
    if (!status_start && !pending_start && !silent_start) {
        char *modes[] = {"--test-status-start", "--test-pending-start", "--test-login-start"};
        for (guint i = 0; i < G_N_ELEMENTS(modes); i++) {
            char *child[] = {argv[0], modes[i], NULL};
            int result;
            g_assert_true(g_spawn_sync(NULL, child, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL, &result, NULL));
            g_assert_true(g_spawn_check_wait_status(result, NULL));
        }
    }
    g_autofree char *display = g_strdup(g_getenv("DISPLAY"));
    GTestDBus *sandbox = g_test_dbus_new(G_TEST_DBUS_NONE);
    g_test_dbus_up(sandbox);
    if (display) g_setenv("DISPLAY", display, TRUE);
    const char *address = g_test_dbus_get_bus_address(sandbox);
    g_setenv("DBUS_SYSTEM_BUS_ADDRESS", address, TRUE);
    g_setenv("GTK_A11Y", "none", TRUE);
    g_setenv("GSETTINGS_BACKEND", "memory", TRUE);
    service = mock_connection(address, BIOS_BUS);
    fwupd = mock_connection(address, FWUPD);
    desktop = mock_connection(address, "org.gnome.SessionManager");
    GDBusConnection *login = mock_connection(address, "org.freedesktop.login1");
    g_autoptr(GDBusNodeInfo) node = g_dbus_node_info_new_for_xml(mock_xml, NULL);
    expose(service, node, BIOS_PATH, BIOS_BUS);
    expose(fwupd, node, "/", FWUPD);
    expose(login, node, "/org/freedesktop/login1", "org.freedesktop.login1.Manager");
    expose(desktop, node, "/org/gnome/SessionManager", "org.gnome.SessionManager");
    expose(desktop, node, "/test/client", "org.gnome.SessionManager.ClientPrivate");
    ui.app = gtk_application_new(BIOS_APP, G_APPLICATION_NON_UNIQUE);
    g_assert_true(g_application_register(G_APPLICATION(ui.app), NULL, NULL));
    g_object_set(gtk_settings_get_default(), "gtk-font-name", "Sans 22", NULL);
    ui.login = silent_start;
    ui.read_only = status_start || silent_start;
    if (pending_start) mock_state = "pending";
    activate(ui.app, NULL);
    if (status_start || pending_start || silent_start) {
        WAIT_FOR(ui.fresh && !ui.busy && !ui.reading);
        g_assert_cmpuint(checks_sent, ==, 0);
        g_assert_cmpuint(installs, ==, 0);
        g_assert_cmpuint(powers, ==, 0);
        g_assert_nonnull(action_button("状態を再確認"));
        if (pending_start) g_assert_true(state("pending"));
        if (status_start) g_assert_null(action_button("配布情報を再確認"));
        g_assert_cmpint(gtk_widget_get_visible(GTK_WIDGET(ui.window)), ==, !silent_start);
        g_test_dbus_stop(sandbox);
        return 0;
    }
    advance("available");
    g_assert_cmpuint(checks_sent, ==, 1);
    click("更新する");
    advance("review");
    preview();
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
    click("今回は見送る");
    advance("idle");
    g_assert_cmpuint(installs, ==, 0);
    click("配布情報を再確認");
    advance("available");
    click("更新する");
    advance("review");
    g_assert_false(gtk_widget_is_sensitive(ui.approve));
    gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), TRUE);
    click("この更新を承認");
    action_clicked(NULL, "Authorize"); /* another activation in the same event loop turn */
    advance("pending");
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
    logout_block = TRUE;
    click("再起動する");
    WAIT_FOR(cancelled == 1);
    advance("pending");
    g_assert_cmpuint(desktop_calls, ==, 0);
    logout_block = FALSE;
    for (guint i = 0; i < 2; i++) {
        mock_desktop = i ? "cinnamon" : "gnome";
        click("再起動する");
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
    click("電源を切る");
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
    mock_power = "reboot";
    g_assert_cmpuint(installs, ==, 1);
    mock_state = "idle";
    click("状態を再確認");
    advance("idle");
    withhold = TRUE;
    click("配布情報を再確認");
    WAIT_FOR(held_check != NULL);
    mock_state = "pending";
    g_assert_true(g_dbus_connection_emit_signal(service, NULL, BIOS_PATH, BIOS_BUS, "Changed", NULL, NULL));
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
