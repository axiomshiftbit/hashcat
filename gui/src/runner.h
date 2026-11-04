/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#pragma once

#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include "managed_process.h"
#include <QTimer>

class Runner : public QObject
{
  Q_OBJECT
public:
  explicit Runner (QObject *parent = nullptr);
  ~Runner () override;
  bool start (const QString &binary, const QStringList &args, const QString &cwd, bool interactive = true, const QString &stdin_file = {});
  bool busy () const;
  bool command (char key);
  void stop ();
  void kill ();
signals:
  void line (const QString &text);
  void status (const QJsonObject &object);
  void finished (int code, bool crashed);
  void started ();
private:
  void drain ();
  void consume (const QByteArray &bytes, bool final = false);
  void release_input ();
  ManagedProcess process;
  QByteArray pending;
  QTimer deadline;
  bool emitted = false, accepting_commands = false;
#ifdef Q_OS_WIN
  void *input = nullptr;
#else
  int master_fd = -1, slave_fd = -1;
#endif
};
