#pragma once

#include <gio/gio.h>

/* AppRun passes an open directory, never a command or executable pathname. */
int portable_take_appdir(void);
void portable_reopen(int dir_fd, GError **error);
void portable_connect_async(GDBusConnection *system, int dir_fd, GCancellable *cancel,
                            GAsyncReadyCallback callback, gpointer data);
GDBusConnection *portable_connect_finish(GAsyncResult *result, GError **error);
