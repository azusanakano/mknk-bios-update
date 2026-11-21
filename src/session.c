#include "session.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define SM "org.gnome.SessionManager"
#define SM_PATH "/org/gnome/SessionManager"
#define CLIENT SM ".ClientPrivate"
#define LOGIN "org.freedesktop.login1"
#define LOGIN_PATH "/org/freedesktop/login1"

typedef struct {
    GDBusConnection *system, *session, *control;
    char *service_owner, *request, *manager, *login, *client;
    gboolean cinnamon, reboot, finished, sent, query_ok;
    guint signal, watch, deadline, query_generation;
    PowerNotice notice;
    PowerDone done;
    gpointer data;
} Power;

static void power_clear(gpointer data)
{
    Power *p = data;
    g_clear_object(&p->system);
    g_clear_object(&p->session);
    g_clear_object(&p->control);
    g_free(p->service_owner);
    g_free(p->request);
    g_free(p->manager);
    g_free(p->login);
    g_free(p->client);
}

static void release(gpointer data)
{
    g_atomic_rc_box_release_full(data, power_clear);
}

static GVariant *call(GDBusConnection *bus, const char *owner, const char *path,
                      const char *interface, const char *method, GVariant *args,
                      const GVariantType *type, GError **error)
{
    return g_dbus_connection_call_sync(bus, owner, path, interface, method, args, type,
                                       G_DBUS_CALL_FLAGS_NO_AUTO_START, 4000, NULL, error);
}

static char *owner_of(GDBusConnection *bus, const char *name, GError **error)
{
    g_autoptr(GVariant) reply = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                     "org.freedesktop.DBus", "GetNameOwner",
                                     g_variant_new("(s)", name), G_VARIANT_TYPE("(s)"), error);
    char *value = NULL;
    if (reply) g_variant_get(reply, "(s)", &value);
    return value;
}

static gboolean unavailable(GError **error, const char *reason)
{
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, reason);
    return FALSE;
}

static gboolean same_session(Power *p, GError **error)
{
    g_autoptr(GVariant) process = call(p->session, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID", g_variant_new("(s)", p->manager),
        G_VARIANT_TYPE("(u)"), error);
    if (!process) return FALSE;
    guint pid;
    g_variant_get(process, "(u)", &pid);
    g_autoptr(GVariant) manager_session = call(p->system, p->login, LOGIN_PATH, LOGIN ".Manager",
        "GetSessionByPID", g_variant_new("(u)", pid), G_VARIANT_TYPE("(o)"), error);
    if (!manager_session) return FALSE;
    g_autoptr(GVariant) gui_session = call(p->system, p->login, LOGIN_PATH, LOGIN ".Manager",
        "GetSessionByPID", g_variant_new("(u)", (guint) getpid()), G_VARIANT_TYPE("(o)"), error);
    if (!gui_session) return FALSE;
    if (!g_variant_equal(manager_session, gui_session))
        return unavailable(error, "この画面と同じログインセッションの終了経路を確認できません。");
    return TRUE;
}

/* The standards checks run on the user's connections, including checks of
 * inhibitors owned by the same uid. Only the session manager requests power. */
static gboolean checks(Power *p, GError **error)
{
    g_autofree char *login = owner_of(p->system, LOGIN, error);
    if (!login) return FALSE;
    g_autofree char *manager = owner_of(p->session, SM, error);
    if (!manager) return FALSE;
    if (!g_str_equal(login, p->login) || !g_str_equal(manager, p->manager))
        return unavailable(error, "終了処理を担当するサービスが変わりました。");
    if (!same_session(p, error)) return FALSE;

    if (p->cinnamon) {
        const char *paths[] = { "/var/run/gdm_socket", "/var/run/mdm_socket", "/tmp/.mdm_socket" };
        for (guint i = 0; i < G_N_ELEMENTS(paths); i++) {
            struct stat st;
            if (stat(paths[i], &st) == 0 || errno != ENOENT)
                return unavailable(error, "旧ディスプレイマネージャーの終了経路を除外できません。");
        }
    }
    const char *method = p->reboot ? "CanReboot" : "CanPowerOff";
    g_autoptr(GVariant) allowed = call(p->system, login, LOGIN_PATH, LOGIN ".Manager",
                                       method, NULL, G_VARIANT_TYPE("(s)"), error);
    if (!allowed) return FALSE;
    const char *permission;
    g_variant_get(allowed, "(&s)", &permission);
    if (!g_str_equal(permission, "yes"))
        return unavailable(error, "現在のセッションで電源操作が許可されていません。");

    g_autoptr(GVariant) locks = call(p->system, login, LOGIN_PATH, LOGIN ".Manager",
                                     "ListInhibitors", NULL, G_VARIANT_TYPE("(a(ssssuu))"), error);
    if (!locks) return FALSE;
    g_autoptr(GVariant) entries = g_variant_get_child_value(locks, 0);
    GVariantIter iter;
    const char *what, *who, *why, *mode;
    guint uid, pid;
    g_variant_iter_init(&iter, entries);
    while (g_variant_iter_loop(&iter, "(&s&s&s&suu)", &what, &who, &why, &mode, &uid, &pid)) {
        g_auto(GStrv) kinds = g_strsplit(what, ":", -1);
        if (g_strv_contains((const char *const *) kinds, "shutdown") && !g_str_equal(mode, "delay")) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_BUSY, "%s が終了を保留しています。%s", who, why);
            return FALSE;
        }
    }
    g_autoptr(GVariant) blocked = call(p->session, manager, SM_PATH, SM, "IsInhibited",
                                       g_variant_new("(u)", 1u), G_VARIANT_TYPE("(b)"), error);
    if (!blocked) return FALSE;
    gboolean inhibited;
    g_variant_get(blocked, "(b)", &inhibited);
    if (inhibited) return unavailable(error, "デスクトップで終了を妨げる作業が進行中です。");
    g_autoptr(GVariant) fresh = call(p->control, p->service_owner, BIOS_PATH, BIOS_BUS,
                                     "RecheckPower", g_variant_new("(s)", p->request),
                                     G_VARIANT_TYPE_UNIT, error);
    return fresh != NULL;
}

static void finish(Power *p, gboolean cancelled, const char *message)
{
    if (p->finished) return;
    p->finished = TRUE;
    if (p->deadline) g_source_remove(p->deadline);
    if (p->signal) g_dbus_connection_signal_unsubscribe(p->session, p->signal);
    if (p->watch) g_bus_unwatch_name(p->watch);
    if (p->client)
        g_dbus_connection_call(p->session, p->manager, SM_PATH, SM, "UnregisterClient",
                               g_variant_new("(o)", p->client), G_VARIANT_TYPE_UNIT,
                               G_DBUS_CALL_FLAGS_NO_AUTO_START, 2000, NULL, NULL, NULL);
    p->done(cancelled, message, p->data);
    release(p);
}

static void respond(Power *p, gboolean ok, const char *reason)
{
    g_dbus_connection_call(p->session, p->manager, p->client, CLIENT, "EndSessionResponse",
                           g_variant_new("(bs)", ok, reason), G_VARIANT_TYPE_UNIT,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, 750, NULL, NULL, NULL);
}

static gboolean deadline(gpointer data)
{
    Power *p = data;
    p->deadline = 0;
    p->query_generation++;
    respond(p, FALSE, "給電状態と起動予約の確認に時間がかかっています。");
    return G_SOURCE_REMOVE;
}

static void check_thread(GTask *task, gpointer source, gpointer data, GCancellable *cancel)
{
    (void) source; (void) cancel;
    g_autoptr(GError) error = NULL;
    if (checks(data, &error)) g_task_return_boolean(task, TRUE);
    else g_task_return_error(task, g_steal_pointer(&error));
}

static void query_done(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source;
    GTask *task = G_TASK(result);
    Power *p = g_task_get_task_data(task);
    g_autoptr(GError) error = NULL;
    gboolean ok = g_task_propagate_boolean(task, &error);
    if (p->finished || GPOINTER_TO_UINT(data) != p->query_generation) return;
    g_clear_handle_id(&p->deadline, g_source_remove);
    p->query_ok = ok;
    respond(p, ok, ok ? "" : error->message);
}

static void session_signal(GDBusConnection *bus, const char *sender, const char *path,
                           const char *iface, const char *name, GVariant *args, gpointer data)
{
    (void) bus; (void) sender; (void) path; (void) iface; (void) args;
    Power *p = data;
    if (g_str_equal(name, "QueryEndSession")) {
        if (!p->sent) {
            respond(p, TRUE, "");
            finish(p, TRUE, "別の終了処理が先に始まりました。");
            return;
        }
        p->query_ok = FALSE;
        ++p->query_generation;
        g_clear_handle_id(&p->deadline, g_source_remove);
        /* A desktop can show its usual waiting prompt while hardware is being
         * read. A late result still belongs to this query until it ends. */
        p->deadline = g_timeout_add_seconds(10, deadline, p);
        g_autoptr(GTask) task = g_task_new(NULL, NULL, query_done, GUINT_TO_POINTER(p->query_generation));
        g_task_set_task_data(task, g_atomic_rc_box_acquire(p), release);
        g_task_run_in_thread(task, check_thread);
    } else if (g_str_equal(name, "CancelEndSession")) {
        finish(p, TRUE, "終了が取り消されました。更新の予約は保持されています。");
    } else if (g_str_equal(name, "EndSession")) {
        ++p->query_generation;
        g_clear_handle_id(&p->deadline, g_source_remove);
        if (!p->sent) {
            respond(p, TRUE, "");
            finish(p, TRUE, "別の終了処理が先に始まりました。");
        } else {
            respond(p, p->query_ok, p->query_ok ? "" : "給電状態と起動予約を確認できません。");
        }
    } else if (g_str_equal(name, "Stop")) {
        finish(p, FALSE, "デスクトップが終了しています。次回ログイン時に結果を確認します。");
    }
}

static void owner_lost(GDBusConnection *bus, const char *name, gpointer data)
{
    (void) bus; (void) name;
    Power *p = data;
    finish(p, !p->sent, "デスクトップとの接続が切れました。状態を再確認してください。");
}

static void desktop_reply(GObject *source, GAsyncResult *result, gpointer data)
{
    Power *p = data;
    g_autoptr(GError) error = NULL;
    g_autoptr(GVariant) reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
    if (!reply && !p->finished) {
        if (g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD) ||
            g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED) ||
            g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS)) {
            finish(p, TRUE, "デスクトップが終了要求を受け付けませんでした。");
        } else {
            /* A missing reply can arrive after the manager has begun logout.
             * Keep answering its queries and do not open a second request. */
            p->notice("終了要求の受付結果が未確定です。デスクトップからの終了または取消の通知を待っています。");
        }
    }
    release(p);
}

static void preflight_done(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source; (void) data;
    GTask *task = G_TASK(result);
    Power *p = g_task_get_task_data(task);
    g_autoptr(GError) error = NULL;
    gboolean ok = g_task_propagate_boolean(task, &error);
    if (p->finished) return;
    if (!ok) {
        finish(p, TRUE, error->message);
        return;
    }
    const char *method = p->cinnamon ? (p->reboot ? "RequestReboot" : "RequestShutdown")
                                      : (p->reboot ? "Reboot" : "Shutdown");
    p->sent = TRUE;
    g_dbus_connection_call(p->session, p->manager, SM_PATH, SM, method, NULL, G_VARIANT_TYPE_UNIT,
                           G_DBUS_CALL_FLAGS_NO_AUTO_START, 120000, NULL, desktop_reply,
                           g_atomic_rc_box_acquire(p));
}

static void register_thread(GTask *task, gpointer source, gpointer data, GCancellable *cancel)
{
    (void) source; (void) cancel;
    Power *p = data;
    g_autoptr(GError) error = NULL;
    p->session = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (p->session) p->manager = owner_of(p->session, SM, &error);
    if (p->manager) p->login = owner_of(p->system, LOGIN, &error);
    if (p->login) {
        g_autoptr(GVariant) reply = call(p->session, p->manager, SM_PATH, SM, "RegisterClient",
                                         g_variant_new("(ss)", BIOS_APP, ""),
                                         G_VARIANT_TYPE("(o)"), &error);
        if (reply) g_variant_get(reply, "(o)", &p->client);
    }
    if (error) g_task_return_error(task, g_steal_pointer(&error));
    else g_task_return_boolean(task, TRUE);
}

static void registered(GObject *source, GAsyncResult *result, gpointer data)
{
    (void) source; (void) data;
    Power *p = g_task_get_task_data(G_TASK(result));
    g_autoptr(GError) error = NULL;
    if (!g_task_propagate_boolean(G_TASK(result), &error)) {
        finish(p, TRUE, error->message);
        return;
    }
    p->signal = g_dbus_connection_signal_subscribe(p->session, p->manager, CLIENT, NULL, p->client,
                                                  NULL, G_DBUS_SIGNAL_FLAGS_NONE, session_signal, p, NULL);
    p->watch = g_bus_watch_name_on_connection(p->session, p->manager, G_BUS_NAME_WATCHER_FLAGS_NONE,
                                              NULL, owner_lost, p, NULL);
    g_autoptr(GTask) task = g_task_new(NULL, NULL, preflight_done, NULL);
    g_task_set_task_data(task, g_atomic_rc_box_acquire(p), release);
    g_task_run_in_thread(task, check_thread);
}

void session_request_power(GDBusConnection *system, GDBusConnection *control, const char *service_owner,
                           const char *request, const char *desktop, const char *action,
                           PowerNotice notice, PowerDone done, gpointer data)
{
    if ((system == control ? !service_owner || !g_dbus_is_unique_name(service_owner) : service_owner != NULL) ||
        !*request ||
        (!g_str_equal(desktop, "gnome") && !g_str_equal(desktop, "cinnamon")) ||
        (!g_str_equal(action, "reboot") && !g_str_equal(action, "shutdown"))) {
        done(TRUE, "このデスクトップの終了経路を確認できません。", data);
        return;
    }
    Power *p = g_atomic_rc_box_new0(Power);
    p->system = g_object_ref(system);
    p->control = g_object_ref(control);
    p->service_owner = g_strdup(service_owner);
    p->request = g_strdup(request);
    p->cinnamon = g_str_equal(desktop, "cinnamon");
    p->reboot = g_str_equal(action, "reboot");
    p->done = done;
    p->notice = notice;
    p->data = data;
    g_autoptr(GTask) task = g_task_new(NULL, NULL, registered, NULL);
    g_task_set_task_data(task, g_atomic_rc_box_acquire(p), release);
    g_task_run_in_thread(task, register_thread);
}
