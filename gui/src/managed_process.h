// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QProcess>

class ManagedProcess : public QProcess
{
public:
  ManagedProcess ();
  ~ManagedProcess () override;
  void kill ();
private:
  void kill_children ();
#ifdef Q_OS_WIN
  void *job = nullptr;
#else
  qint64 group = 0;
#endif
};
