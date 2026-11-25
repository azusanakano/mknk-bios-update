#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gio/gunixfdlist.h>
#include <json-glib/json-glib.h>

#include "session.h"
#include "portable.h"

#define UNKNOWN "確認できません"
#define FWUPD "org.freedesktop.fwupd"
#define FOCUS_KEY "mknk-review-focus"

/* fwupd and logind use the GUI's system bus. Portable app methods use a
 * separate root-authenticated peer with no D-Bus destination name. */
static struct {
    GtkApplication *app;
    GtkWindow *window;
    GtkWidget *model, *current, *stack, *page, *history, *history_text, *notice;
    GtkWidget *approve, *recovery, *details, *actions;
    GDBusConnection *bus, *control;
    GCancellable *startup, *power_preflight;
    JsonObject *view, *rendered_view;
    const char *saved_focus, *pending_panel;
    char *owner, *stage, *previous_state, *deferred_plan, *power_plan, *power_action;
    guint watch, changes, timer, startup_timeout;
    gulong closed;
    int appdir_fd;
    guint64 generation;
    gboolean opening, busy, reading, fresh, read_only, explicit_plan, closing, first_status, login;
    gboolean preparing, abandon_prepare, portable, wait_on_close, focus_initialized;
} ui;

typedef struct {
    guint64 generation;
    GDBusConnection *control, *system;
    char *owner;
    char *id;
    char *fwupd, *device, *target, *checksum, *sha512, *remote, *component;
} Request;

static Request *request_new(const char *id)
{
    Request *r = g_new0(Request, 1);
    r->generation = ui.generation;
    r->control = g_object_ref(ui.control);
    r->system = g_object_ref(ui.bus);
    r->owner = g_strdup(ui.owner);
    r->id = g_strdup(id);
    return r;
}

static void request_free(Request *r)
{
    g_object_unref(r->control);
    g_object_unref(r->system);
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

static gboolean same_service(Request *r)
{
    return r->control == ui.control && r->system == ui.bus && g_strcmp0(r->owner, ui.owner) == 0;
}

static const char *view_field(JsonObject *view, const char *key)
{
    JsonNode *n = view ? json_object_get_member(view, key) : NULL;
    return n && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : "";
}

static gboolean view_flag(JsonObject *view, const char *key)
{
    JsonNode *n = view ? json_object_get_member(view, key) : NULL;
    return n && json_node_get_value_type(n) == G_TYPE_BOOLEAN && json_node_get_boolean(n);
}

static const char *field(const char *key) { return view_field(ui.view, key); }
static gboolean flag(const char *key) { return view_flag(ui.view, key); }
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
    g_object_set_data(G_OBJECT(w), FOCUS_KEY, (gpointer) name);
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
    return !ui.read_only && ui.control && ui.fresh && !ui.busy && !ui.reading && !ui.closing;
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

static gboolean can_request_power(void)
{
    return !ui.read_only && state("pending") && flag("can_power") && *field("plan") &&
           (g_str_equal(field("power"), "reboot") || g_str_equal(field("power"), "shutdown"));
}

static gboolean matching_power_confirmation(void)
{
    return ui.power_plan && can_request_power() && g_str_equal(ui.power_plan, field("plan")) &&
           g_str_equal(ui.power_action, field("power"));
}

static void clear_power_confirmation(void)
{
    g_clear_pointer(&ui.power_plan, g_free);
    g_clear_pointer(&ui.power_action, g_free);
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
    g_object_set_data(G_OBJECT(w), FOCUS_KEY, (gpointer) action);
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

static gboolean same_review(void)
{
    if (!state("review") || !*field("plan") || !g_str_equal(view_field(ui.rendered_view, "state"), "review"))
        return FALSE;
    const char *content[] = {
        "plan", "model", "current", "target", "scope", "source", "checked", "changes", "power",
        "signed", "synced", "checksum", "cab_sha512", "remote_id", "appstream_id", "device", "daemon_owner",
        "recovery_detail",
    };
    for (guint i = 0; i < G_N_ELEMENTS(content); i++) {
        if (!g_str_equal(view_field(ui.rendered_view, content[i]), field(content[i]))) return FALSE;
    }
    return view_flag(ui.rendered_view, "recovery_required") == flag("recovery_required") &&
           view_flag(ui.rendered_view, "cached") == flag("cached");
}

static const char *widget_focus_key(GtkWidget *widget)
{
    for (; widget; widget = gtk_widget_get_parent(widget)) {
        const char *key = g_object_get_data(G_OBJECT(widget), FOCUS_KEY);
        if (key) return key;
    }
    return NULL;
}

static GtkWidget *find_focus(GtkWidget *root, const char *key)
{
    if (g_strcmp0(g_object_get_data(G_OBJECT(root), FOCUS_KEY), key) == 0) return root;
    for (GtkWidget *child = gtk_widget_get_first_child(root); child; child = gtk_widget_get_next_sibling(child)) {
        GtkWidget *match = find_focus(child, key);
        if (match) return match;
    }
    return NULL;
}

static void render(void)
{
    GtkWidget *page = column(14), *focus = NULL;
    const char *s = field("state");
    gboolean review = state("review") && *field("plan");
    gboolean keep_review = same_review();
    gboolean recovered = keep_review && ui.recovery && gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.recovery));
    gboolean expanded = keep_review && ui.details && gtk_expander_get_expanded(GTK_EXPANDER(ui.details));
    if (!matching_power_confirmation()) clear_power_confirmation();
    const char *pending_panel = NULL;
    if (state("pending")) {
        pending_panel = ui.power_plan ? "power-confirmation" :
                        g_strcmp0(ui.deferred_plan, field("plan")) == 0 ? "deferred" : "pending";
    }
    gboolean keep_pending = pending_panel && g_strcmp0(ui.pending_panel, pending_panel) == 0 &&
        *field("plan") && g_str_equal(view_field(ui.rendered_view, "plan"), field("plan")) &&
        g_str_equal(view_field(ui.rendered_view, "power"), field("power"));
    if (!keep_review && !keep_pending) {
        ui.saved_focus = NULL;
        ui.focus_initialized = FALSE;
    } else if (ui.previous_state && *ui.previous_state) {
        /* GTK may move focus when the current button is disabled during a status read. */
        ui.saved_focus = widget_focus_key(gtk_window_get_focus(ui.window));
    }
    g_clear_pointer(&ui.rendered_view, json_object_unref);
    if (review || pending_panel) ui.rendered_view = json_object_ref(ui.view);
    ui.pending_panel = pending_panel;
    const char *focus_state = pending_panel ? pending_panel : s;
    if (ui.busy || ui.reading || !ui.fresh) focus_state = "";
    gboolean transition = g_strcmp0(ui.previous_state, focus_state) != 0;
    gboolean entering_view = *focus_state && (review || pending_panel ? !ui.focus_initialized : transition);
    GtkWidget *old = ui.page;
    ui.page = page;
    ui.approve = NULL;
    ui.recovery = NULL;
    ui.details = NULL;
    gtk_stack_add_child(GTK_STACK(ui.stack), page);
    gtk_stack_set_visible_child(GTK_STACK(ui.stack), page);
    if (old) gtk_stack_remove(GTK_STACK(ui.stack), old);
    identity();
    const char *heading = *field("title") ? field("title") :
                          ui.portable && !ui.control ? "この PC の BIOS 情報" : "端末の状態を確認";
    append(page, label(heading, "title-2"));
    if (ui.portable && !ui.control) {
        const char *explanation = ui.read_only
            ? "この画面では、端末から読み取った機種と BIOS 版を表示します。更新情報を確認するには、通常モードで開き直してください。"
            : "更新情報を確認するには管理者認証が必要です。認証後にこの PC の更新計画を読み取り、計画がない場合は配布元を確認します。";
        append(page, label(ui.opening ? "管理者認証と端末サービスへの接続を待っています。" : explanation, NULL));
    }
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
        ui.details = gtk_expander_new("配布情報と計画の詳細");
        g_object_set_data(G_OBJECT(ui.details), FOCUS_KEY, "ReviewDetails");
        GtkWidget *details = column(6);
        info(details, "計画 ID", field("plan"));
        info(details, "配布元 ID", field("remote_id"));
        info(details, "AppStream 部品 ID", field("appstream_id"));
        info(details, "CAB の SHA-256", field("checksum"));
        info(details, "CAB の SHA-512", field("cab_sha512"));
        info(details, "署名日時", field("signed"));
        info(details, "上流との同期時点", field("synced"));
        gtk_expander_set_child(GTK_EXPANDER(ui.details), details);
        gtk_expander_set_expanded(GTK_EXPANDER(ui.details), expanded);
        append(page, ui.details);
    }
    if (state("review") && *field("recovery_detail")) append(page, label(field("recovery_detail"), NULL));
    if (state("review") && flag("recovery_required") && !ui.read_only) {
        ui.recovery = gtk_check_button_new();
        g_object_set_data(G_OBJECT(ui.recovery), FOCUS_KEY, "ReviewRecovery");
        const char *affirmation = "この PC が起動しなくても、暗号化した各 OS の回復手段を紙や別端末で参照できます（Ubuntu の TPM 暗号化・Windows の BitLocker など）";
        GtkWidget *caption = label(affirmation, NULL);
        gtk_check_button_set_child(GTK_CHECK_BUTTON(ui.recovery), caption);
        gtk_check_button_set_active(GTK_CHECK_BUTTON(ui.recovery), recovered);
        gtk_accessible_update_property(GTK_ACCESSIBLE(ui.recovery), GTK_ACCESSIBLE_PROPERTY_LABEL, affirmation, -1);
        g_signal_connect(ui.recovery, "toggled", G_CALLBACK(recovery_toggled), NULL);
        append(page, ui.recovery);
    }
    if (state("pending")) {
        append(page, label(shutdown ? "予約は保持されます。次の電源投入時に PC が適用を試みます。"
                                    : "予約は保持されます。次の通常の再起動で PC が適用を試みます。", NULL));
    }
    if (ui.read_only && !ui.portable && !strstr(field("detail"), "ランチャー"))
        append(page, label("閲覧用に開いています。更新を行うには、アプリのランチャーから「更新計画を開く」を選んでください。", NULL));
    if (ui.stage) append(page, label(ui.stage, "heading"));
    /* The device and action bar remain in place as the central details scroll. */
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(ui.actions)) != NULL)
        gtk_flow_box_remove(GTK_FLOW_BOX(ui.actions), child);
    if (ui.portable && !ui.control) {
        GtkWidget *open = ui.read_only
            ? button(ui.actions, "通常モードで開き直す", "ReopenPortable", FALSE)
            : button(ui.actions, "更新情報を確認", "OpenPortable", TRUE);
        gtk_widget_set_sensitive(open, !ui.opening && !ui.busy && !ui.closing);
    } else if (ui.preparing) {
        GtkWidget *cancel = button(ui.actions, "今回は見送る", "AbandonPrepare", FALSE);
        gtk_widget_set_sensitive(cancel, !ui.abandon_prepare);
    } else if (!ui.read_only && state("review") && *field("plan") && flag("can_approve")) {
        focus = button(ui.actions, "今回は見送る", "Dismiss", FALSE);
        gtk_widget_set_sensitive(focus, writable());
        ui.approve = button(ui.actions, "この更新を承認", "Authorize", TRUE);
        gtk_widget_set_sensitive(ui.approve, can_approve() && (!ui.recovery || recovered));
    } else if (!ui.read_only && state("available") && flag("can_prepare") && *field("token")) {
        gtk_widget_set_sensitive(button(ui.actions, "更新する", "Prepare", TRUE), writable());
    } else if (state("pending")) {
        if (ui.power_plan) {
            append(page, label(shutdown ? "この PC の電源を切りますか？" : "この PC を再起動しますか？", "heading"));
            append(page, label("開いている作業を保存してから進んでください。", NULL));
            focus = button(ui.actions, "キャンセル", "CancelPower", FALSE);
            gtk_widget_set_sensitive(button(ui.actions, shutdown ? "電源を切る操作を続ける" : "再起動を続ける",
                                             "ConfirmPower", TRUE), writable());
        } else if (ui.deferred_plan && g_str_equal(ui.deferred_plan, field("plan"))) {
            if (!ui.read_only) focus = button(ui.actions, "起動操作を表示", "ShowPower", FALSE);
        } else if (!ui.read_only) {
            focus = button(ui.actions, "あとで", "Later", FALSE);
            gtk_widget_set_sensitive(focus, !ui.busy);
            if (can_request_power())
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
    if (!ui.read_only && flag("can_take_over") && *field("plan"))
        gtk_widget_set_sensitive(button(ui.actions, "管理者として承認を解除", "TakeOver", FALSE), writable());
    if (!ui.read_only && can_check())
        gtk_widget_set_sensitive(button(ui.actions, "配布情報を再確認", "Check", FALSE), writable());
    const char *history = field("history");
    set_text(ui.history_text, *history ? history : ui.view ? "表示できる履歴はありません。" :
             ui.portable && !ui.read_only ? "「更新情報を確認」で端末の更新履歴を読み取れます。" :
             ui.portable ? "更新履歴は通常モードで管理者認証を行うと確認できます。" : "履歴を取得できません。");
    GtkWidget *restore_focus = NULL;
    if (ui.saved_focus) {
        restore_focus = find_focus(page, ui.saved_focus);
        if (!restore_focus) restore_focus = find_focus(ui.actions, ui.saved_focus);
    }
    if (restore_focus && gtk_widget_is_sensitive(restore_focus)) gtk_widget_grab_focus(restore_focus);
    else if (focus && entering_view) gtk_widget_grab_focus(focus);
#if GTK_CHECK_VERSION(4, 14, 0)
    if (entering_view)
        gtk_accessible_announce(GTK_ACCESSIBLE(ui.stack), heading, GTK_ACCESSIBLE_ANNOUNCEMENT_PRIORITY_MEDIUM);
#endif
    if ((review || pending_panel) && *focus_state) ui.focus_initialized = TRUE;
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
static void clear_control(void);

static void status_done(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!same_service(r)) return;
    ui.reading = FALSE;
    if (r->generation != ui.generation) {
        schedule_status();
        render();
        return;
    }
    if (!reply || !receive_view(reply)) {
        if (ui.portable && !ui.busy) {
            g_dbus_connection_close(ui.control, NULL, NULL, NULL);
            clear_control();
            ui.first_status = FALSE;
        }
        ui.fresh = FALSE;
        g_clear_pointer(&ui.view, json_object_unref);
        error_notice("端末サービスから現在の状態を取得できません。", error);
    }
    if (ui.login) {
        ui.login = FALSE;
        if (!ui.fresh || (!*field("plan") && !flag("result_this_boot") &&
                          !state("pending") && !state("issuing") && !state("uncertain"))) {
            g_application_quit(G_APPLICATION(ui.app));
            return;
        }
        gtk_window_present(ui.window);
    }
    render();
    if (ui.first_status && ui.fresh) {
        ui.first_status = FALSE;
        if (!*field("plan") && !flag("result_this_boot") && can_check() && writable())
            action_clicked(NULL, "Check");
    }
}

static void refresh(void)
{
    if (ui.reading || ui.closing) return;
    if (!ui.control) {
        if (ui.portable) render();
        else connect_service();
        return;
    }
    ui.reading = TRUE;
    ui.fresh = FALSE;
    ++ui.generation;
    render();
    g_dbus_connection_call(ui.control, ui.owner, BIOS_PATH, BIOS_BUS, "Status", NULL,
                           G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000,
                           NULL, status_done, request_new(NULL));
}

static gboolean delayed_status(gpointer data)
{
    (void) data;
    ui.timer = 0;
    if (ui.control) refresh();
    return G_SOURCE_REMOVE;
}

static void schedule_status(void)
{
    if (!ui.timer && ui.control && !ui.closing)
        ui.timer = g_timeout_add(120, delayed_status, NULL);
}

static void changed(GDBusConnection *bus, const char *sender, const char *path,
                    const char *iface, const char *name, GVariant *args, gpointer data)
{
    (void) path; (void) iface; (void) name; (void) args; (void) data;
    if (bus != ui.control || g_strcmp0(sender, ui.owner) != 0) return;
    ++ui.generation;
    ui.fresh = FALSE;
    render();
    schedule_status();  /* local reconciliation only, never catalog refresh */
}

static void clear_control(void)
{
    ++ui.generation;
    if (ui.power_preflight) g_cancellable_cancel(ui.power_preflight);
    if (ui.changes) g_dbus_connection_signal_unsubscribe(ui.control, ui.changes);
    if (ui.closed) g_signal_handler_disconnect(ui.control, ui.closed);
    ui.changes = 0;
    ui.closed = 0;
    ui.reading = FALSE;
    ui.fresh = FALSE;
    g_clear_handle_id(&ui.timer, g_source_remove);
    g_clear_object(&ui.control);
    g_clear_pointer(&ui.owner, g_free);
    g_clear_pointer(&ui.view, json_object_unref);
    g_clear_pointer(&ui.rendered_view, json_object_unref);
    clear_power_confirmation();
}

static void private_closed(GDBusConnection *bus, gboolean remote, GError *error, gpointer data)
{
    (void) remote; (void) error; (void) data;
    if (bus != ui.control) return;
    clear_control();
    g_clear_object(&ui.bus);
    ui.first_status = FALSE;
    notice("端末サービスとの接続が終了しました。更新計画は「更新情報を確認」から読み直せます。");
    render();
}

static void use_control(GDBusConnection *bus, const char *owner)
{
    clear_control();
    ui.control = g_object_ref(bus);
    ui.owner = g_strdup(owner);
    ui.opening = FALSE;
    ui.changes = g_dbus_connection_signal_subscribe(bus, owner, BIOS_BUS, "Changed", BIOS_PATH, NULL,
                                                  G_DBUS_SIGNAL_FLAGS_NONE, changed, NULL, NULL);
    if (ui.portable) {
        ui.closed = g_signal_connect(bus, "closed", G_CALLBACK(private_closed), NULL);
        if (g_dbus_connection_is_closed(bus)) {
            private_closed(bus, TRUE, NULL, NULL);
            return;
        }
    }
    notice(NULL);
    refresh();
}

static void appeared(GDBusConnection *bus, const char *name, const char *owner, gpointer data)
{
    (void) name; (void) data;
    if (bus == ui.bus && !ui.closing) use_control(bus, owner);
}

static void vanished(GDBusConnection *bus, const char *name, gpointer data)
{
    (void) name; (void) data;
    if (bus && bus != ui.bus) return;
    clear_control();
    ui.opening = FALSE;
    notice("端末サービスに接続できません。この PC から読み取れた機種と BIOS 版を表示しています。");
    render();
    if (ui.login) g_application_quit(G_APPLICATION(ui.app));
}

static void finish_startup(void)
{
    g_clear_handle_id(&ui.startup_timeout, g_source_remove);
    g_clear_object(&ui.startup);
    ui.opening = FALSE;
}

static gboolean startup_expired(gpointer data)
{
    (void) data;
    ui.startup_timeout = 0;
    g_cancellable_cancel(ui.startup);
    return G_SOURCE_REMOVE;
}

static void portable_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GDBusConnection) peer = portable_connect_finish(result, &error);
    finish_startup();
    if (ui.closing || G_DBUS_CONNECTION(source) != ui.bus) return;
    if (!peer || g_dbus_connection_is_closed(peer)) {
        g_clear_object(&ui.bus);
        ui.first_status = FALSE;
        error_notice(g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)
                     ? "管理者認証または接続が時間内に完了しませんでした。「更新情報を確認」でやり直せます。"
                     : "更新計画を開けませんでした。機種と現在の BIOS 版は引き続き確認できます。", error);
        render();
        return;
    }
    use_control(peer, NULL);
}

static void bus_unavailable(GError *error)
{
    finish_startup();
    error_notice("システムバスに接続できません。", error);
    render();
    if (ui.login) g_application_quit(G_APPLICATION(ui.app));
}

static void bus_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source; (void) data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GDBusConnection) bus = g_dbus_connection_new_for_address_finish(result, &error);
    if (ui.closing) return;
    if (!bus) {
        bus_unavailable(error);
        return;
    }
    g_set_object(&ui.bus, bus);
    g_dbus_connection_set_exit_on_close(ui.bus, FALSE);
    if (ui.portable) {
        portable_connect_async(bus, ui.appdir_fd, ui.startup, portable_ready, NULL);
        return;
    }
    ui.watch = g_bus_watch_name_on_connection(bus, BIOS_BUS, G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
                                              appeared, vanished, NULL, NULL);
}

static void connect_service(void)
{
    if (ui.opening) return;
    ui.opening = TRUE;
    if (ui.portable) {
        ui.startup = g_cancellable_new();
        ui.startup_timeout = g_timeout_add_seconds(180, startup_expired, NULL);
    }
    if (ui.watch) g_bus_unwatch_name(ui.watch);
    ui.watch = 0;
    g_clear_object(&ui.bus);
    g_autoptr(GError) error = NULL;
    g_autofree char *address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, ui.startup, &error);
    if (!address) {
        bus_unavailable(error);
        return;
    }
    /* Other libraries may still reference GIO's closed process-wide bus after a restart. */
    g_dbus_connection_new_for_address(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, ui.startup, bus_ready, NULL);
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

static void close_and_quit(void)
{
    if (ui.portable && ui.control) g_dbus_connection_close(ui.control, NULL, NULL, NULL);
    clear_control();
    g_application_quit(G_APPLICATION(ui.app));
}

static void end(void)
{
    ui.busy = FALSE;
    ui.wait_on_close = FALSE;
    g_clear_object(&ui.power_preflight);
    g_clear_pointer(&ui.stage, g_free);
    if (ui.closing) close_and_quit();
    else render();
}

static void send_view(const char *method, GVariant *args);

static void view_done(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (ui.closing && !ui.wait_on_close) return;
    gboolean attached = same_service(r);
    gboolean same = r->generation == ui.generation && attached;
    if (ui.preparing) {
        ui.preparing = FALSE;
        gboolean abandon = ui.abandon_prepare;
        ui.abandon_prepare = FALSE;
        /* Dismiss only the draft returned by this Prepare, even if an unrelated
         * observation arrived during the download. Dismiss cannot issue a permit. */
        if (abandon && reply && attached) {
            const char *json;
            g_variant_get(reply, "(&s)", &json);
            g_autoptr(JsonParser) parser = json_parser_new();
            if (json_parser_load_from_data(parser, json, -1, NULL) &&
                JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
                JsonObject *draft = json_node_get_object(json_parser_get_root(parser));
                const char *plan = view_field(draft, "prepared_draft");
                if (*plan) {
                    send_view("Dismiss", g_variant_new("(s)", plan));
                    return;
                }
            }
        }
    }
    if (!attached) {
        schedule_status();
        end();
        return;
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
    g_dbus_connection_call(ui.control, ui.owner, BIOS_PATH, BIOS_BUS, method, args,
                           G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START |
                           G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION, 600000,
                           NULL, view_done, request_new(NULL));
}

static gboolean install_definitely_rejected(GDBusMessage *reply, const char *owner)
{
    if (!reply || g_dbus_message_get_message_type(reply) != G_DBUS_MESSAGE_TYPE_ERROR) return FALSE;
    const char *sender = g_dbus_message_get_sender(reply);
    const char *name = g_dbus_message_get_error_name(reply);
    if (g_strcmp0(sender, "org.freedesktop.DBus") == 0) {
        return g_strcmp0(name, "org.freedesktop.DBus.Error.NameHasNoOwner") == 0 ||
               g_strcmp0(name, "org.freedesktop.DBus.Error.ServiceUnknown") == 0 ||
               g_strcmp0(name, "org.freedesktop.DBus.Error.AccessDenied") == 0;
    }
    GVariant *body = g_dbus_message_get_body(reply);
    if (g_strcmp0(sender, owner) != 0 || g_strcmp0(name, FWUPD ".AuthFailed") != 0 ||
        !body || !g_variant_is_of_type(body, G_VARIANT_TYPE("(s)"))) return FALSE;
    /* fwupd's polkit denial precedes fu_engine_install_releases. Other authentication
     * errors may originate during installation and cannot release the operation. */
    const char *detail;
    g_variant_get(body, "(&s)", &detail);
    return g_str_equal(detail, "Failed to obtain auth");
}

static void install_done(GObject *source, GAsyncResult *result, gpointer data)
{
    Request *operation = data;
    GDBusConnection *bus = G_DBUS_CONNECTION(source);
    g_autoptr(GError) error = NULL;
    g_autoptr(GDBusMessage) reply = g_dbus_connection_send_message_with_reply_finish(bus, result, &error);
    const char *method = "Report";
    GVariant *args;
    if (install_definitely_rejected(reply, operation->fwupd)) {
        method = "ReportRejection";
        args = g_variant_new("(s)", operation->id);
        notice("更新準備の依頼が配置前に拒否されました。端末の予約と状態を照合します。");
    } else {
        GVariant *body = reply ? g_dbus_message_get_body(reply) : NULL;
        gboolean accepted = reply && g_dbus_message_get_message_type(reply) == G_DBUS_MESSAGE_TYPE_METHOD_RETURN &&
            g_strcmp0(g_dbus_message_get_sender(reply), operation->fwupd) == 0 &&
            (!body || g_variant_is_of_type(body, G_VARIANT_TYPE_UNIT));
        if (!accepted) {
            if (reply) g_dbus_message_to_gerror(reply, &error);
            error_notice("受付結果が未確定です。同じ更新は再送せず、予約と実機を照合します。", error);
        }
        args = g_variant_new("(sb)", operation->id, accepted);
    }
    g_dbus_connection_call(operation->control, operation->owner, BIOS_PATH, BIOS_BUS, method, args,
                           G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 30000, NULL, view_done, operation);
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

static void authorization_declined(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!reply && same_service(r))
        error_notice("未送信の許可を取り消せませんでした。端末の記録を読み直します。", error);
    schedule_status();
    end();
}

static void decline_authorization(Request *r)
{
    g_dbus_connection_call(r->control, r->owner, BIOS_PATH, BIOS_BUS, "DeclineAuthorization",
                           g_variant_new("(s)", r->id), G_VARIANT_TYPE_UNIT,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, G_MAXINT, NULL, authorization_declined, r);
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
    if (ui.closing || g_strcmp0(owner, r->fwupd) != 0 || g_strcmp0(device, r->device) != 0 || !valid_cab(fds, index) ||
        !same_service(r) || g_dbus_connection_is_closed(r->control)) {
        if (!ui.closing) notice("送信条件を確認できません。未使用の許可を取り消します。");
        decline_authorization(g_steal_pointer(&r));
        return;
    }
    GVariantBuilder options;
    g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&options, "{sv}", "install-flags", g_variant_new_uint64(0));
    g_variant_builder_add(&options, "{sv}", "reason", g_variant_new_string("user-action"));
    g_free(ui.stage);
    ui.stage = g_strdup("検証済みの配布ファイルを fwupd に渡しています。");
    render();
    GDBusConnection *system = r->system;
    g_autoptr(GDBusMessage) install = g_dbus_message_new_method_call(owner, "/", FWUPD, "Install");
    g_dbus_message_set_flags(install, G_DBUS_MESSAGE_FLAGS_NO_AUTO_START |
                                      G_DBUS_MESSAGE_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION);
    g_dbus_message_set_body(install, g_variant_new("(sha{sv})", device, index, &options));
    g_dbus_message_set_unix_fd_list(install, fds);
    g_dbus_connection_send_message_with_reply(system, install, G_DBUS_SEND_MESSAGE_FLAGS_NONE, G_MAXINT,
                                              NULL, NULL, install_done, g_steal_pointer(&r));
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
    if (ui.closing) return;
    if (!reply || !has_reviewed_release(reply, r) || !same_service(r) ||
        ui.generation != r->generation) {
        error_notice("この画面から確認した更新候補が承認内容と一致しません。配布情報を見直してください。", error);
        schedule_status();
        end();
        return;
    }
    Request *checked = g_steal_pointer(&r);
    /* The permit is durable. Keep receiving while the service waits for the
     * verification worker and machine locks. */
    ui.wait_on_close = TRUE;
    g_dbus_connection_call_with_unix_fd_list(checked->control, checked->owner, BIOS_PATH, BIOS_BUS, "Authorize",
                                            g_variant_new("(s)", checked->id), G_VARIANT_TYPE("(sssh)"),
                                            G_DBUS_CALL_FLAGS_NO_AUTO_START |
                                            G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
                                            G_MAXINT, NULL, NULL, authorized, checked);
}

static void power_recorded(GObject *source, GAsyncResult *result, gpointer data)
{
    g_autoptr(Request) r = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!reply && same_service(r)) error_notice("終了要求の結果を記録できません。状態を再確認してください。", error);
    schedule_status();
    end();
}

static void power_complete(gboolean cancelled, const char *message, gpointer data)
{
    Request *r = data;
    if (same_service(r)) notice(message);
    g_dbus_connection_call(r->control, r->owner, BIOS_PATH, BIOS_BUS, "ReplyPower",
                           g_variant_new("(sb)", r->id, cancelled), G_VARIANT_TYPE_UNIT,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, G_MAXINT, NULL, power_recorded, r);
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
    gboolean matches = g_str_equal(r->id, action) && !ui.closing && same_service(r);
    g_free(r->id);
    r->id = g_strdup(id);
    if (!matches) {
        power_complete(TRUE, "終了要求を取り消しました。予約は保持されています。", g_steal_pointer(&r));
        return;
    }
    g_free(ui.stage);
    ui.stage = g_strdup("デスクトップの終了条件を確認しています。");
    render();
    Request *operation = g_steal_pointer(&r);
    ui.power_preflight = g_cancellable_new();
    session_request_power(operation->system, operation->control, operation->owner, id, desktop, action,
                          ui.power_preflight, notice, power_complete, operation);
}

static void action_clicked(GtkButton *button_widget, gpointer data)
{
    (void) button_widget;
    const char *action = data;
    if (g_str_equal(action, "OpenPortable") && ui.portable && !ui.read_only && !ui.control &&
        !ui.busy && !ui.opening && !ui.closing) {
        ui.first_status = TRUE;
        notice(NULL);
        connect_service();
        return;
    }
    if (g_str_equal(action, "ReopenPortable") && ui.portable && ui.read_only && !ui.closing) {
        g_autoptr(GError) error = NULL;
        portable_reopen(ui.appdir_fd, &error);
        error_notice("同じ AppImage を通常モードで開いてください。", error);
        return;
    }
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
    if (g_str_equal(action, "CancelPower") && ui.power_plan) {
        clear_power_confirmation();
        render();
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
    } else if (g_str_equal(action, "TakeOver") && flag("can_take_over") && *field("plan")) {
        begin("管理者認証と、以前の承認が未送信であることを確認しています。");
        send_view("TakeOver", g_variant_new("(s)", field("plan")));
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
    } else if (g_str_equal(action, "Power") && !ui.power_plan && can_request_power()) {
        ui.power_plan = g_strdup(field("plan"));
        ui.power_action = g_strdup(field("power"));
        render();
    } else if (g_str_equal(action, "ConfirmPower") && matching_power_confirmation()) {
        clear_power_confirmation();
        begin("給電状態・起動先・更新の予約を再確認しています。");
        /* Keep the connection until an allocated request can be acknowledged. */
        ui.wait_on_close = TRUE;
        g_dbus_connection_call(ui.control, ui.owner, BIOS_PATH, BIOS_BUS, "Power",
                               g_variant_new("(s)", field("plan")), G_VARIANT_TYPE("(sss)"),
                               G_DBUS_CALL_FLAGS_NO_AUTO_START, G_MAXINT, NULL, power_ready,
                               request_new(field("power")));
    }
}

static gboolean closing(GtkWindow *window, gpointer data)
{
    (void) data;
    ui.closing = TRUE;
    if (ui.startup) g_cancellable_cancel(ui.startup);
    if (ui.power_preflight) g_cancellable_cancel(ui.power_preflight);
    gtk_widget_set_visible(GTK_WIDGET(window), FALSE);
    if (!ui.wait_on_close) close_and_quit();
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
    ui.first_status = !ui.read_only && !ui.portable;
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
    if (!ui.portable) connect_service();
    else if (ui.login) g_application_quit(G_APPLICATION(app));
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
    ui.portable = g_strcmp0(g_getenv("MKNK_BIOS_PORTABLE"), "1") == 0;
    ui.appdir_fd = ui.portable ? portable_take_appdir() : -1;
    g_set_application_name("BIOS 更新");
    ui.app = gtk_application_new(BIOS_APP, G_APPLICATION_NON_UNIQUE);
    g_object_set(ui.app, "register-session", FALSE, NULL);
    g_signal_connect(ui.app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(ui.app), argc, argv);
    if (ui.startup) g_cancellable_cancel(ui.startup);
    finish_startup();
    if (ui.portable && ui.control) g_dbus_connection_close_sync(ui.control, NULL, NULL);
    clear_control();
    g_clear_object(&ui.power_preflight);
    if (ui.watch) g_bus_unwatch_name(ui.watch);
    if (ui.appdir_fd >= 0) close(ui.appdir_fd);
    g_clear_object(&ui.bus);
    g_clear_object(&ui.app);
    g_free(ui.previous_state);
    g_free(ui.stage);
    g_free(ui.deferred_plan);
    return status;
}
