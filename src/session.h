#pragma once

#include <gio/gio.h>

#define BIOS_BUS "io.github.mknk.BiosUpdate1"
#define BIOS_PATH "/io/github/mknk/BiosUpdate1"
#define BIOS_APP "io.github.mknk.BiosUpdate"

typedef void (*PowerDone)(gboolean definitely_cancelled, const char *message, gpointer data);
typedef void (*PowerNotice)(const char *message);

/* Keep the registered client's connection alive until cancellation, session stop,
 * or loss of the manager. The completion callback runs on the GTK main context. */
void session_request_power(GDBusConnection *system, GDBusConnection *control, const char *service_owner,
                           const char *request, const char *desktop, const char *action,
                           PowerNotice notice, PowerDone done, gpointer data);
