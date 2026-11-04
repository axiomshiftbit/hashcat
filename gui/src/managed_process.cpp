// SPDX-License-Identifier: GPL-3.0-or-later
#include "managed_process.h"
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

ManagedProcess::ManagedProcess ()
{
#ifdef Q_OS_WIN
  job = CreateJobObjectW (nullptr, nullptr);
  if (job)
  {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject (job, JobObjectExtendedLimitInformation, &limits, sizeof (limits));
  }
#else
  setChildProcessModifier ([] { setsid (); });
#endif
  connect (this, &QProcess::started, this, [this]
  {
#ifdef Q_OS_WIN
    const HANDLE child = OpenProcess (PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, DWORD (processId ()));
    if (child)
    {
      if (job) AssignProcessToJobObject (job, child);
      CloseHandle (child);
    }
#else
    group = processId ();
#endif
  });
  connect (this, qOverload<int, QProcess::ExitStatus> (&QProcess::finished), this, [this] { kill_children (); });
}

ManagedProcess::~ManagedProcess ()
{
  blockSignals (true);
  kill ();
  if (state () != QProcess::NotRunning) waitForFinished (3000);
#ifdef Q_OS_WIN
  if (job) CloseHandle (job);
#endif
}

void ManagedProcess::kill_children ()
{
#ifdef Q_OS_WIN
  if (job) TerminateJobObject (job, 1);
#else
  if (group > 0) ::kill (-pid_t (group), SIGKILL);
  group = 0;
#endif
}

void ManagedProcess::kill ()
{
  kill_children ();
  if (state () != QProcess::NotRunning) QProcess::kill ();
}
