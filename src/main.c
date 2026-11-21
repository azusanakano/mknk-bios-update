#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gio/gunixfdlist.h>
#include <json-glib/json-glib.h>

#include "session.h"

#define UNKNOWN "確認できません"
#define FWUPD "org.freedesktop.fwupd"

/* The process has one window and one system-bus connection. Desktop actions
 * launch a fresh process so a status-only instance cannot acquire write rights. */
static struct {
    GtkApplication *app;
    GtkWindow *window;
    GtkWidget *model, *current, *stack, *page, *history, *history_text, *notice;
    GtkWidget *approve, *recovery, *actions;
    GDBusConnection *bus;
    JsonObject *view;
    char *owner, *stage, *previous_state, *deferred_plan;
    guint watch, changes, timer;
    guint64 generation;
    gboolean opening, busy, reading, fresh, read_only, explicit_plan, closing, first_status, login;
    gboolean preparing, abandon_prepare;
} ui;

typedef struct {
    guint64 generation;
    char *owner;
    char *id;
    char *fwupd, *device, *target, *checksum, *sha512, *remote, *component;
} Request;

static Request *request_new(const char *id)
{
    Request *r = g_new0(Request, 1);
    r->generation = ui.generation;
    r->owner = g_strdup(ui.owner);
    r->id = g_strdup(id);
    return r;
}

static void request_free(Request *r)
{
    g_free(r->owner);
    g_free(r->id);
    g_free(r->fwupd);
    g_free(r->device);
    g_free(r->target);
    g_free(r->checksum);
    g_free(r->sha512);
    g_free(r->remote);
    g_free(r->component);
    g_free(r);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(Request, request_free)

static const char *field(const char *key)
{
    JsonNode *n = ui.view ? json_object_get_member(ui.view, key) : NULL;
    return n && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : "";
}

static gboolean flag(const char *key)
{
    JsonNode *n = ui.view ? json_object_get_member(ui.view, key) : NULL;
    return n && json_node_get_value_type(n) == G_TYPE_BOOLEAN && json_node_get_boolean(n);
}

static gboolean state(const char *value) { return g_str_equal(field("state"), value); }

static gboolean hex_id(const char *s, size_t length)
{
    if (strlen(s) != length) return FALSE;
    for (; *s; s++) if (!g_ascii_isxdigit(*s)) return FALSE;
    return TRUE;
}

static GtkWidget *label(const char *text, const char *style)
{
    GtkWidget *w = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(w), 0.0);
    gtk_label_set_wrap(GTK_LABEL(w), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(w), PANGO_WRAP_WORD_CHAR);
    if (style) gtk_widget_add_css_class(w, style);
    return w;
}

static GtkWidget *column(int spacing) { return gtk_box_new(GTK_ORIENTATION_VERTICAL, spacing); }
static void append(GtkWidget *box, GtkWidget *w) { gtk_box_append(GTK_BOX(box), w); }
static void margins(GtkWidget *w, int h, int v)
{
    gtk_widget_set_margin_start(w, h);
    gtk_widget_set_margin_end(w, h);
    gtk_widget_set_margin_top(w, v);
    gtk_widget_set_margin_bottom(w, v);
}

static void set_text(GtkWidget *label_widget, const char *text)
{
    gtk_label_set_text(GTK_LABEL(label_widget), text);
}

static void info(GtkWidget *box, const char *name, const char *value)
{
    if (!*value) return;
    g_autofree char *line = g_strdup_printf("%s　%s", name, value);
    GtkWidget *w = label(line, NULL);
    gtk_label_set_selectable(GTK_LABEL(w), TRUE);
    append(box, w);
}

static char *dmi(const char *file)
{
    g_autofree char *path = g_build_filename("/sys/class/dmi/id", file, NULL);
    g_autofree char *bytes = NULL;
    if (!g_file_get_contents(path, &bytes, NULL, NULL) || !g_utf8_validate(bytes, -1, NULL))
        return g_strdup(UNKNOWN);
    g_strstrip(bytes);
    return g_strdup(*bytes ? bytes : UNKNOWN);
}

static void identity(void)
{
    g_autofree char *model = *field("model") ? g_strdup(field("model")) : dmi("product_name");
    g_autofree char *current = *field("current") ? g_strdup(field("current")) : dmi("bios_version");
    g_autofree char *line = g_strconcat("現在の BIOS　", current, NULL);
    g_autofree char *accessible_model = g_strconcat("機種　", model, NULL);
    set_text(ui.model, model);
    gtk_accessible_update_property(GTK_ACCESSIBLE(ui.model), GTK_ACCESSIBLE_PROPERTY_LABEL, accessible_model, -1);
    set_text(ui.current, line);
}

static void notice(const char *message)
{
    set_text(ui.notice, message ? message : "");
    gtk_widget_set_visible(ui.notice, message && *message);
#if GTK_CHECK_VERSION(4, 14, 0)
    if (message && *message)
        gtk_accessible_announce(GTK_ACCESSIBLE(ui.notice), message, GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_MEDIUM);
#endif
}

static void error_notice(const char *context, GError *error)
{
    if (error) g_dbus_error_strip_remote_error(error);
    g_autofree char *message = g_strdup_printf("%s%s%s", context, error ? "\n" : "",
                                               error ? error->message : "");
    notice(message);
}

static gboolean writable(void)
{
    return !ui.read_only && ui.owner && ui.fresh && !ui.busy && !ui.reading && !ui.closing;
}

static gboolean can_approve(void)
{
    return writable() && state("review") && flag("can_approve") &&
           *field("plan") && *field("current") && *field("target") && *field("scope") &&
           *field("source") && hex_id(field("checksum"), 64) &&
           *field("appstream_id") && *field("remote_id") &&
           g_dbus_is_unique_name(field("daemon_owner")) && hex_id(field("device"), 40) &&
           (g_str_equal(field("power"), "reboot") || g_str_equal(field("power"), "shutdown"));
}

static gboolean can_check(void)
{
    return flag("can_check") && (state("idle") || state("available") || state("current") ||
                                 state("complete") || state("hold"));
}

static void refresh(void);
static void connect_service(void);
static void action_clicked(GtkButton *button, gpointer data);

static GtkWidget *button(GtkWidget *box, const char *text, const char *action, gboolean primary)
{
    GtkWidget *w = gtk_button_new_with_label(text);
    GtkWidget *caption = gtk_button_get_child(GTK_BUTTON(w));
    if (GTK_IS_LABEL(caption)) gtk_label_set_wrap(GTK_LABEL(caption), TRUE);
    if (primary) gtk_widget_add_css_class(w, "suggested-action");
    gtk_widget_set_halign(w, GTK_ALIGN_START);
    g_signal_connect(w, "clicked", G_CALLBACK(action_clicked), (gpointer) action);
    gtk_flow_box_insert(GTK_FLOW_BOX(box), w, -1);
    GtkWidget *item = gtk_widget_get_parent(w);
    gtk_widget_set_focusable(item, FALSE);
    /* FlowBox selects keyboard destinations by the wrapper's sensitivity. */
    g_object_bind_property(w, "sensitive", item, "sensitive", G_BINDING_SYNC_CREATE);
    return w;
}

static void manual_link(GtkWidget *box, const char *caption, const char *address)
{
    if (!*address) return;
    g_autoptr(GUri) uri = g_uri_parse(address, G_URI_FLAGS_NONE, NULL);
    if (!uri || !g_uri_get_scheme(uri) || g_ascii_strcasecmp(g_uri_get_scheme(uri), "https") != 0 ||
        !g_uri_get_host(uri) || !*g_uri_get_host(uri) || g_uri_get_userinfo(uri)) return;
    GtkWidget *link = gtk_link_button_new_with_label(address, caption);
    gtk_widget_set_halign(link, GTK_ALIGN_START);
    append(box, link);
}

static void recovery_toggled(GtkCheckButton *check, gpointer data)
{
    (void) data;
    if (ui.approve)
        gtk_widget_set_sensitive(ui.approve, can_approve() && gtk_check_button_get_active(check));
}

static void render(void)
{
    GtkWidget *page = column(14), *focus = NULL;
    const char *s = field("state");
    const char *focus_state = (ui.busy || ui.reading || !ui.fresh) ? "" : s;
    gboolean transition = g_strcmp0(ui.previous_state, focus_state) != 0;
    GtkWidget *old = ui.page;
    ui.page = page;
    ui.approve = NULL;
    ui.recovery = NULL;
    gtk_stack_add_child(GTK_STACK(ui.stack), page);
    gtk_stack_set_visible_child(GTK_STACK(ui.stack), page);
    if (old) gtk_stack_remove(GTK_STACK(ui.stack), old);
    identity();
    const char *heading = *field("title") ? field("title") : "端末の状態を確認";
    append(page, label(heading, "title-2"));
    if (*field("detail")) append(page, label(field("detail"), NULL));
    if (*field("target")) {
        if (state("review")) {
            g_autofree char *version = g_strdup_printf("%s → %s", field("current"), field("target"));
            info(page, "承認する版", version);
        } else {
            info(page, state("pending") ? "予約した版" : "対象版", field("target"));
        }
    }
    info(page, "対象部品・承認範囲", field("scope"));
    info(page, "配布元", field("source"));
    info(page, flag("cached") ? "前回確認" : "確認日時", field("checked"));
    info(page, "変更内容", field("changes"));
    gboolean shutdown = g_str_equal(field("power"), "shutdown");
    if (shutdown || g_str_equal(field("power"), "reboot"))
        info(page, "必要な起動操作", shutdown ? "電源を切り、次に電源を入れる" : "再起動");
    if (*field("signed") || *field("synced") || *field("plan") || *field("checksum")) {
        GtkWidget *expander = gtk_expander_new("配布情報と計画の詳細");
        GtkWidget *details = column(6);
        info(details, "計画 ID", field("plan"));
        info(details, "配布元 ID", field("remote_id"));
        info(details, "AppStream 部品 ID", field("appstream_id"));
        info(details, "CAB の SHA-256", field("checksum"));
        info(details, "CAB の SHA-512", field("cab_sha512"));
        info(details, "署名日時", field("signed"));
        info(details, "上流との同期時点", field("synced"));
        gtk_expander_set_child(GTK_EXPANDER(expander), details);
        append(page, expander);
    }
    if (state("review") && *field("recovery_detail")) append(page, label(field("recovery_detail"), NULL));
    if (state("review") && flag("recovery_required") && !ui.read_only) {
        ui.recovery = gtk_check_button_new();
        const char *affirmation = "この PC が起動しなくても、暗号化した各 OS の回復手段を紙や別端末で参照できます（Ubuntu の TPM 暗号化・Windows の BitLocker など）";
        GtkWidget *caption = label(affirmation, NULL);
        gtk_check_button_set_child(GTK_CHECK_BUTTON(ui.recovery), caption);
        gtk_accessible_update_property(GTK_ACCESSIBLE(ui.recovery), GTK_ACCESSIBLE_PROPERTY_LABEL, affirmation, -1);
        g_signal_connect(ui.recovery, "toggled", G_CALLBACK(recovery_toggled), NULL);
        append(page, ui.recovery);
    }
    if (state("pending")) {
        append(page, label(shutdown ? "予約は保持されます。次の電源投入時に PC が適用を試みます。"
                                    : "予約は保持されます。次の通常の再起動で PC が適用を試みます。", NULL));
    }
    if (ui.read_only && !strstr(field("detail"), "ランチャー"))
        append(page, label("閲覧用に開いています。更新を行うには、アプリのランチャーから「更新計画を開く」を選んでください。", NULL));
    if (ui.stage) append(page, label(ui.stage, "heading"));
    /* The device and action bar remain in place as the central details scroll. */
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(ui.actions)) != NULL)
        gtk_flow_box_remove(GTK_FLOW_BOX(ui.actions), child);
    if (ui.preparing) {
        GtkWidget *cancel = button(ui.actions, "今回は見送る", "AbandonPrepare", FALSE);
        gtk_widget_set_sensitive(cancel, !ui.abandon_prepare);
    } else if (!ui.read_only && state("review") && *field("plan") && flag("can_approve")) {
        focus = button(ui.actions, "今回は見送る", "Dismiss", FALSE);
        gtk_widget_set_sensitive(focus, writable());
        ui.approve = button(ui.actions, "この更新を承認", "Authorize", TRUE);
        gtk_widget_set_sensitive(ui.approve, can_approve() && !ui.recovery);
    } else if (!ui.read_only && state("available") && flag("can_prepare") && *field("token")) {
        gtk_widget_set_sensitive(button(ui.actions, "更新する", "Prepare", TRUE), writable());
    } else if (state("pending")) {
        if (ui.deferred_plan && g_str_equal(ui.deferred_plan, field("plan"))) {
            if (!ui.read_only) focus = button(ui.actions, "起動操作を表示", "ShowPower", FALSE);
        } else if (!ui.read_only) {
            focus = button(ui.actions, "あとで", "Later", FALSE);
            gtk_widget_set_sensitive(focus, !ui.busy);
            if (flag("can_power") && *field("plan") && (shutdown || g_str_equal(field("power"), "reboot")))
                gtk_widget_set_sensitive(button(ui.actions, shutdown ? "電源を切る" : "再起動する", "Power", TRUE),
                                         writable());
        }
    }
    if (state("hold")) {
        manual_link(page, "メーカーの更新手順", field("support_url"));
        manual_link(page, "メーカーの復旧手順", field("recovery_url"));
    }
    gtk_widget_set_sensitive(button(ui.actions, "状態を再確認", "Status", FALSE), !ui.reading && !ui.opening);
    if (!ui.read_only && flag("can_replan") && *field("plan"))
        gtk_widget_set_sensitive(button(ui.actions, "更新計画を作り直す", "Replan", FALSE), writable());
    if (!ui.read_only && can_check())
        gtk_widget_set_sensitive(button(ui.actions, "配布情報を再確認", "Check", FALSE), writable());
    const char *history = field("history");
    set_text(ui.history_text, *history ? history : (ui.view ? "表示できる履歴はありません。" : "履歴を取得できません。"));
    if (focus && transition && *focus_state) gtk_widget_grab_focus(focus);
#if GTK_CHECK_VERSION(4, 14, 0)
    if (transition && *focus_state)
        gtk_accessible_announce(GTK_ACCESSIBLE(ui.stack), heading, GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_MEDIUM);
#endif
    g_free(ui.previous_state);
    ui.previous_state = g_strdup(focus_state);
}

static gboolean receive_view(GVariant *reply)
{
    const char *json;
    g_variant_get(reply, "(&s)", &json);
    g_autoptr(JsonParser) parser = json_parser_new();
    if (!json_parser_load_from_data(parser, json, -1, NULL)) return FALSE;
    JsonNode *root = json_parser_get_root(parser);
    if (!JSON_NODE_HOLDS_OBJECT(root)) return FALSE;
    JsonObject *view = json_node_get_object(root);
    if (!json_object_has_member(view, "state")) return FALSE;
    g_clear_pointer(&ui.view, json_object_unref);
    ui.view = json_object_ref(view);
    ui.fresh = TRUE;
    return TRUE;
}

static void schedule_status(void);

static void status_done(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    ui.reading = FALSE;
    if (r->generation != ui.generation || g_strcmp0(r->owner, ui.owner) != 0) {
        schedule_status();
        render();
        return;
    }
    if (!reply || !receive_view(reply)) {
        ui.fresh = FALSE;
        g_clear_pointer(&ui.view, json_object_unref);
        error_notice("端末サービスから現在の状態を取得できません。", error);
    }
    if (ui.login) {
        ui.login = FALSE;
        if (!ui.fresh || (!*field("plan") && !state("pending") && !state("issuing") && !state("uncertain"))) {
            g_application_quit(G_APPLICATION(ui.app));
            return;
        }
        gtk_window_present(ui.window);
    }
    render();
    if (ui.first_status && ui.fresh) {
        ui.first_status = FALSE;
        if (state("idle") && !*field("plan") && can_check() && writable())
            action_clicked(NULL, "Check");
    }
}

static void refresh(void)
{
    if (ui.reading || ui.closing) return;
    if (!ui.bus || !ui.owner) {
        connect_service();
        return;
    }
    ui.reading = TRUE;
    ui.fresh = FALSE;
    ++ui.generation;
    render();
    g_dbus_connection_call(ui.bus, ui.owner, BIOS_PATH, BIOS_BUS, "Status", NULL,
                           G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000,
                           NULL, status_done, request_new(NULL));
}

static gboolean delayed_status(gpointer data)
{
    (void) data;
    ui.timer = 0;
    if (ui.owner) refresh();
    return G_SOURCE_REMOVE;
}

static void schedule_status(void)
{
    if (!ui.timer && ui.owner && !ui.closing)
        ui.timer = g_timeout_add(120, delayed_status, NULL);
}

static void changed(GDBusConnection *bus, const char *sender, const char *path,
                    const char *iface, const char *name, GVariant *args, gpointer data)
{
    (void) bus; (void) path; (void) iface; (void) name; (void) args; (void) data;
    if (g_strcmp0(sender, ui.owner) != 0) return;
    ++ui.generation;
    ui.fresh = FALSE;
    render();
    schedule_status();  /* local reconciliation only, never catalog refresh */
}

static void appeared(GDBusConnection *bus, const char *name, const char *owner, gpointer data)
{
    (void) name; (void) data;
    g_free(ui.owner);
    ui.owner = g_strdup(owner);
    ++ui.generation;
    ui.opening = FALSE;
    if (ui.changes) g_dbus_connection_signal_unsubscribe(bus, ui.changes);
    ui.changes = g_dbus_connection_signal_subscribe(bus, owner, BIOS_BUS, "Changed", BIOS_PATH, NULL,
                                                  G_DBUS_SIGNAL_FLAGS_NONE, changed, NULL, NULL);
    notice(NULL);
    refresh();
}

static void vanished(GDBusConnection *bus, const char *name, gpointer data)
{
    (void) name; (void) data;
    ++ui.generation;
    ui.opening = FALSE;
    ui.fresh = FALSE;
    if (ui.changes && bus) g_dbus_connection_signal_unsubscribe(bus, ui.changes);
    ui.changes = 0;
    g_clear_pointer(&ui.owner, g_free);
    g_clear_pointer(&ui.view, json_object_unref);
    notice("端末サービスに接続できません。この PC から読み取れた機種と BIOS 版を表示しています。");
    render();
    if (ui.login) g_application_quit(G_APPLICATION(ui.app));
}

static void bus_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source; (void) data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GDBusConnection) bus = g_bus_get_finish(result, &error);
    if (!bus) {
        ui.opening = FALSE;
        error_notice("システムバスに接続できません。", error);
        render();
        if (ui.login) g_application_quit(G_APPLICATION(ui.app));
        return;
    }
    g_set_object(&ui.bus, bus);
    g_dbus_connection_set_exit_on_close(ui.bus, FALSE);
    ui.watch = g_bus_watch_name_on_connection(bus, BIOS_BUS, G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
                                              appeared, vanished, NULL, NULL);
}

static void connect_service(void)
{
    if (ui.opening) return;
    ui.opening = TRUE;
    if (ui.watch) g_bus_unwatch_name(ui.watch);
    ui.watch = 0;
    g_bus_get(G_BUS_TYPE_SYSTEM, NULL, bus_ready, NULL);
    render();
}

static void begin(const char *stage)
{
    ui.busy = TRUE;
    ui.fresh = FALSE;
    ++ui.generation;
    g_free(ui.stage);
    ui.stage = g_strdup(stage);
    notice(NULL);
    render();
}

static void end(void)
{
    ui.busy = FALSE;
    g_clear_pointer(&ui.stage, g_free);
    if (ui.closing) g_application_quit(G_APPLICATION(ui.app));
    else render();
}

static void send_view(const char *method, GVariant *args);

static void view_done(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    gboolean same = r->generation == ui.generation && g_strcmp0(r->owner, ui.owner) == 0;
    if (ui.preparing) {
        ui.preparing = FALSE;
        gboolean abandon = ui.abandon_prepare;
        ui.abandon_prepare = FALSE;
        /* Dismiss only the draft returned by this Prepare, even if an unrelated
         * observation arrived during the download. Dismiss cannot issue a permit. */
        if (abandon && reply && g_strcmp0(r->owner, ui.owner) == 0) {
            const char *json;
            g_variant_get(reply, "(&s)", &json);
            g_autoptr(JsonParser) parser = json_parser_new();
            if (json_parser_load_from_data(parser, json, -1, NULL) &&
                JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
                JsonObject *draft = json_node_get_object(json_parser_get_root(parser));
                const char *plan = json_object_get_string_member_with_default(draft, "plan", "");
                if (plan && *plan && g_strcmp0(json_object_get_string_member_with_default(draft, "state", ""), "review") == 0) {
                    send_view("Dismiss", g_variant_new("(s)", plan));
                    return;
                }
            }
        }
    }
    if (!reply) {
        error_notice("操作の結果を確認できません。端末の記録を読み直します。", error);
        ui.fresh = FALSE;
    }
    if (!reply || !same || !receive_view(reply)) {
        ui.fresh = FALSE;
        schedule_status();
    }
    end();
}

static void send_view(const char *method, GVariant *args)
{
    g_dbus_connection_call(ui.bus, ui.owner, BIOS_PATH, BIOS_BUS, method, args,
                           G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START |
                           G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION, 600000,
                           NULL, view_done, request_new(NULL));
}

static void report(GDBusConnection *bus, Request *operation, gboolean accepted)
{
    g_dbus_connection_call(bus, operation->owner, BIOS_PATH, BIOS_BUS, "Report",
                           g_variant_new("(sb)", operation->id, accepted), G_VARIANT_TYPE("(s)"),
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000, NULL, view_done, operation);
}

static void install_done(GObject *source, GAsyncResult *result, gpointer data)
{
    GDBusConnection *bus = G_DBUS_CONNECTION(source);
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_with_unix_fd_list_finish(bus, NULL, result, &error);
    if (!reply)
        error_notice("受付結果が未確定です。同じ更新は再送せず、予約と実機を照合します。", error);
    report(bus, data, reply != NULL);
}

/* Only the immutable file descriptor from the service is forwarded. The
 * SHA-256 displayed for this plan was verified before the permit was issued. */
static gboolean valid_cab(GUnixFDList *fds, gint index)
{
    if (!fds || index != 0 || g_unix_fd_list_get_length(fds) != 1) return FALSE;
    const gint *fd = g_unix_fd_list_peek_fds(fds, NULL);
    int seals = fcntl(fd[0], F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat st;
    return seals >= 0 && (seals & required) == required && fstat(fd[0], &st) == 0 &&
           S_ISREG(st.st_mode) && st.st_size > 0 && lseek(fd[0], 0, SEEK_CUR) == 0;
}

static void authorized(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    GDBusConnection *bus = G_DBUS_CONNECTION(source);
    g_autoptr(GUnixFDList) fds = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_with_unix_fd_list_finish(bus, &fds, result, &error);
    if (!reply) {
        error_notice("送信許可の結果を確認できません。端末の記録を読み直します。", error);
        schedule_status();
        end();
        return;
    }
    const char *op, *owner, *device;
    gint index;
    g_variant_get(reply, "(&s&s&sh)", &op, &owner, &device, &index);
    if (g_strcmp0(op, r->id) != 0) {
        notice("送信許可の計画 ID が承認内容と一致しません。端末の記録を読み直します。");
        schedule_status();
        end();
        return;
    }
    if (g_strcmp0(owner, r->fwupd) != 0 || g_strcmp0(device, r->device) != 0 || !valid_cab(fds, index) ||
        ui.closing || g_strcmp0(r->owner, ui.owner) != 0 || bus != ui.bus) {
        notice("対象または配布ファイルの送信条件を確認できません。端末の記録を読み直します。");
        report(bus, g_steal_pointer(&r), FALSE);
        return;
    }
    GVariantBuilder options;
    g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&options, "{sv}", "install-flags", g_variant_new_uint64(0));
    g_variant_builder_add(&options, "{sv}", "reason", g_variant_new_string("user-action"));
    g_free(ui.stage);
    ui.stage = g_strdup("検証済みの配布ファイルを fwupd に渡しています。");
    render();
    g_dbus_connection_call_with_unix_fd_list(bus, owner, "/", FWUPD, "Install",
                                            g_variant_new("(sha{sv})", device, index, &options),
                                            G_VARIANT_TYPE_UNIT, G_DBUS_CALL_FLAGS_NO_AUTO_START |
                                            G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
                                            G_MAXINT, fds, NULL, install_done, g_steal_pointer(&r));
}

static gboolean has_reviewed_release(GVariant *reply, Request *r)
{
    g_autoptr(GVariant) releases = g_variant_get_child_value(reply, 0);
    GVariantIter iter;
    GVariant *entry;
    gboolean found = FALSE;
    g_variant_iter_init(&iter, releases);
    while ((entry = g_variant_iter_next_value(&iter))) {
        g_autoptr(GVariant) release = entry;
        const char *version, *checksums, *remote, *component;
        if (!g_variant_lookup(release, "Version", "&s", &version) || !g_str_equal(version, r->target) ||
            !g_variant_lookup(release, "RemoteId", "&s", &remote) || !g_str_equal(remote, r->remote) ||
            !g_variant_lookup(release, "AppstreamId", "&s", &component) || !g_str_equal(component, r->component))
            continue;
        if (!g_variant_lookup(release, "Checksum", "&s", &checksums)) return FALSE;
        /* fwupd 2.0.20 serializes the container checksums as a comma-separated string. */
        g_auto(GStrv) values = g_strsplit(checksums, ",", -1);
        gboolean strong = FALSE;
        for (guint i = 0; values[i]; i++) {
            size_t length = strlen(values[i]);
            if (length != 64 && length != 128) continue;
            const char *digest = length == 64 ? r->checksum : r->sha512;
            if (!hex_id(digest, length) || g_ascii_strcasecmp(values[i], digest) != 0) return FALSE;
            strong = TRUE;
        }
        if (!strong) return FALSE;
        found = TRUE;
    }
    return found;
}

static void user_candidates(GObject *source, GAsyncResult *result, gpointer data)
{
    GDBusConnection *bus = G_DBUS_CONNECTION(source);
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(bus, result, &error);
    if (!reply || !has_reviewed_release(reply, r) || ui.closing || ui.bus != bus ||
        ui.generation != r->generation || g_strcmp0(ui.owner, r->owner) != 0) {
        error_notice("この画面から確認した更新候補が承認内容と一致しません。配布情報を見直してください。", error);
        schedule_status();
        end();
        return;
    }
    Request *checked = g_steal_pointer(&r);
    g_dbus_connection_call_with_unix_fd_list(bus, checked->owner, BIOS_PATH, BIOS_BUS, "Authorize",
                                            g_variant_new("(s)", checked->id), G_VARIANT_TYPE("(sssh)"),
                                            G_DBUS_CALL_FLAGS_NO_AUTO_START |
                                            G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
                                            120000, NULL, NULL, authorized, checked);
}

typedef struct {
    GDBusConnection *bus;
    Request *request;
} PowerReport;

static void power_recorded(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!reply) error_notice("終了要求の結果を記録できません。状態を再確認してください。", error);
    schedule_status();
    end();
}

static void power_complete(gboolean cancelled, const char *message, gpointer data)
{
    PowerReport *p = data;
    notice(message);
    g_dbus_connection_call(p->bus, p->request->owner, BIOS_PATH, BIOS_BUS, "ReplyPower",
                           g_variant_new("(sb)", p->request->id, cancelled), G_VARIANT_TYPE_UNIT,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, power_recorded, NULL);
    request_free(p->request);
    g_object_unref(p->bus);
    g_free(p);
}

static void power_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    GDBusConnection *bus = G_DBUS_CONNECTION(source);
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(bus, result, &error);
    if (!reply) {
        error_notice("終了条件を確認できません。更新の予約は保持されています。", error);
        schedule_status();
        end();
        return;
    }
    const char *id, *desktop, *action;
    g_variant_get(reply, "(&s&s&s)", &id, &desktop, &action);
    gboolean matches = g_str_equal(r->id, action) && !ui.closing && bus == ui.bus &&
                       g_strcmp0(ui.owner, r->owner) == 0;
    g_free(r->id);
    r->id = g_strdup(id);
    PowerReport *p = g_new0(PowerReport, 1);
    p->bus = g_object_ref(bus);
    p->request = g_steal_pointer(&r);
    if (!matches) {
        power_complete(TRUE, "終了要求を取り消しました。予約は保持されています。", p);
        return;
    }
    g_free(ui.stage);
    ui.stage = g_strdup("デスクトップの終了条件と確認画面を待っています。");
    render();
    session_request_power(bus, p->request->owner, id, desktop, action, notice, power_complete, p);
}

static void action_clicked(GtkButton *button_widget, gpointer data)
{
    (void) button_widget;
    const char *action = data;
    if (g_str_equal(action, "AbandonPrepare") && ui.preparing) {
        ui.abandon_prepare = TRUE;
        notice("今回は見送ります。進行中の検証が終了したら承認待ちの計画を閉じます。");
        render();
        return;
    }
    if (g_str_equal(action, "Status")) {
        ui.first_status = FALSE;
        notice(NULL);
        refresh();
        return;
    }
    if (g_str_equal(action, "Later") && state("pending") && !ui.busy) {
        g_free(ui.deferred_plan);
        ui.deferred_plan = g_strdup(field("plan"));
        notice("更新の予約を保持しています。起動操作は、都合のよいときに行ってください。");
        render();
        return;
    }
    if (g_str_equal(action, "ShowPower") && state("pending") && !ui.busy) {
        g_clear_pointer(&ui.deferred_plan, g_free);
        notice(NULL);
        refresh();
        return;
    }
    if (!writable()) return;
    if (g_str_equal(action, "Prepare") && state("available") && flag("can_prepare") && *field("token")) {
        ui.preparing = TRUE;
        begin("配布ファイルを取得し、署名と適用先を確認しています。");
        send_view("Prepare", g_variant_new("(s)", field("token")));
    } else if (g_str_equal(action, "Check") && can_check()) {
        begin("配布元の情報と、この機種に適用できる版を照合しています。");
        send_view("Check", NULL);
    } else if (g_str_equal(action, "Replan") && flag("can_replan") && *field("plan")) {
        begin("以前の処理と起動予約の解消を確認しています。");
        send_view("Replan", g_variant_new("(s)", field("plan")));
    } else if (g_str_equal(action, "Dismiss") && state("review") && flag("can_approve") && *field("plan")) {
        begin("今回の承認を見送っています。");
        send_view("Dismiss", g_variant_new("(s)", field("plan")));
    } else if (g_str_equal(action, "Authorize") && can_approve() &&
               (!ui.recovery || gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.recovery)))) {
        begin("承認した計画と現在の端末を再照合しています。");
        Request *r = request_new(field("plan"));
        r->fwupd = g_strdup(field("daemon_owner"));
        r->device = g_strdup(field("device"));
        r->target = g_strdup(field("target"));
        r->checksum = g_strdup(field("checksum"));
        r->sha512 = g_strdup(field("cab_sha512"));
        r->remote = g_strdup(field("remote_id"));
        r->component = g_strdup(field("appstream_id"));
        g_dbus_connection_call(ui.bus, r->fwupd, "/", FWUPD, "GetUpgrades", g_variant_new("(s)", r->device),
                               G_VARIANT_TYPE("(aa{sv})"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000,
                               NULL, user_candidates, r);
    } else if (g_str_equal(action, "Power") && state("pending") && flag("can_power") && *field("plan") &&
               (g_str_equal(field("power"), "reboot") || g_str_equal(field("power"), "shutdown"))) {
        begin("給電状態・起動先・更新の予約を再確認しています。");
        g_dbus_connection_call(ui.bus, ui.owner, BIOS_PATH, BIOS_BUS, "Power",
                               g_variant_new("(s)", field("plan")), G_VARIANT_TYPE("(sss)"),
                               G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000, NULL, power_ready,
                               request_new(field("power")));
    }
}

static gboolean closing(GtkWindow *window, gpointer data)
{
    (void) data;
    if (ui.busy) {
        ui.closing = TRUE;
        gtk_widget_set_visible(GTK_WIDGET(window), FALSE);
        return TRUE;
    }
    g_application_quit(G_APPLICATION(ui.app));
    return TRUE;
}

static void toggle_history(GtkToggleButton *toggle, gpointer data)
{
    (void) data;
    gboolean active = gtk_toggle_button_get_active(toggle);
    gtk_revealer_set_reveal_child(GTK_REVEALER(ui.history), active);
    if (active) gtk_widget_grab_focus(ui.history_text);
}

static void activate(GtkApplication *app, gpointer data)
{
    (void) data;
    if (ui.window) {
        if (!ui.login) gtk_window_present(ui.window);
        return;
    }
    ui.window = GTK_WINDOW(gtk_application_window_new(app));
    ui.first_status = !ui.read_only;
    gtk_window_set_default_size(ui.window, 640, 620);
    gtk_window_set_title(ui.window, "BIOS 更新");
    g_signal_connect(ui.window, "close-request", G_CALLBACK(closing), NULL);
    GtkWidget *bar = gtk_header_bar_new();
    GtkWidget *toggle = gtk_toggle_button_new_with_label("履歴");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(bar), toggle);
    gtk_window_set_titlebar(ui.window, bar);
    GtkWidget *outer = column(0);
    gtk_window_set_child(ui.window, outer);
    GtkWidget *device = column(5);
    margins(device, 24, 14);
    append(outer, device);
    append(device, label("この PC", "heading"));
    ui.model = label("", "title-1");
    ui.current = label("", NULL);
    gtk_label_set_selectable(GTK_LABEL(ui.model), TRUE);
    gtk_label_set_selectable(GTK_LABEL(ui.current), TRUE);
    append(device, ui.model);
    append(device, ui.current);
    append(outer, gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    append(outer, scroll);
    GtkWidget *body = column(14);
    margins(body, 24, 18);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), body);
    ui.notice = label("", NULL);
    gtk_widget_set_visible(ui.notice, FALSE);
    append(body, ui.notice);
    ui.stack = gtk_stack_new();
    gtk_stack_set_vhomogeneous(GTK_STACK(ui.stack), FALSE);
    append(body, ui.stack);
    ui.history = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(ui.history), GTK_REVEALER_TRANSITION_TYPE_NONE);
    GtkWidget *history_box = column(10);
    append(history_box, gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    append(history_box, label("更新の履歴", "title-3"));
    ui.history_text = label("", NULL);
    gtk_label_set_selectable(GTK_LABEL(ui.history_text), TRUE);
    append(history_box, ui.history_text);
    gtk_revealer_set_child(GTK_REVEALER(ui.history), history_box);
    append(body, ui.history);
    append(outer, gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    ui.actions = gtk_flow_box_new();
    margins(ui.actions, 18, 10);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(ui.actions), GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(ui.actions), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(ui.actions), 6);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(ui.actions), 4);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(ui.actions), 4);
    append(outer, ui.actions);
    g_signal_connect(toggle, "toggled", G_CALLBACK(toggle_history), NULL);
    render();
    if (!ui.login) gtk_window_present(ui.window);
    connect_service();
}

int main(int argc, char **argv)
{
    GOptionEntry options[] = {
        {"status-only", 0, 0, G_OPTION_ARG_NONE, &ui.read_only, "端末の状態を閲覧する", NULL},
        {"open-plan", 0, 0, G_OPTION_ARG_NONE, &ui.explicit_plan, "更新計画を開く", NULL},
        {"login", 0, 0, G_OPTION_ARG_NONE, &ui.login, "ログイン時に未完了の計画と今回の結果を確認する", NULL},
        {0}
    };
    g_autoptr(GOptionContext) context = g_option_context_new("— BIOS 更新");
    g_option_context_add_main_entries(context, options, NULL);
    g_autoptr(GError) error = NULL;
    if (!g_option_context_parse(context, &argc, &argv, &error) || argc != 1 ||
        (ui.explicit_plan && (ui.read_only || ui.login))) {
        g_printerr("%s\n", error ? error->message : "起動オプションを確認してください。");
        return 2;
    }
    ui.read_only = ui.read_only || ui.login;
    g_set_application_name("BIOS 更新");
    ui.app = gtk_application_new(BIOS_APP, G_APPLICATION_NON_UNIQUE);
    g_object_set(ui.app, "register-session", FALSE, NULL);
    g_signal_connect(ui.app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(ui.app), argc, argv);
    if (ui.timer) g_source_remove(ui.timer);
    if (ui.changes) g_dbus_connection_signal_unsubscribe(ui.bus, ui.changes);
    if (ui.watch) g_bus_unwatch_name(ui.watch);
    g_clear_object(&ui.bus);
    g_clear_object(&ui.app);
    g_clear_pointer(&ui.view, json_object_unref);
    g_free(ui.previous_state);
    g_free(ui.stage);
    g_free(ui.deferred_plan);
    g_free(ui.owner);
    return status;
}
