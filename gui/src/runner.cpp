/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "runner.h"
#include "lang.h"

#include <QJsonDocument>
#include <QRegularExpression>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#endif

Runner::Runner (QObject *parent) : QObject (parent)
{
  process.setProcessChannelMode (QProcess::MergedChannels);
  deadline.setSingleShot (true);
  connect (&deadline, &QTimer::timeout, this, &Runner::kill);
  connect (&process, &QProcess::readyReadStandardOutput, this, &Runner::drain);
  connect (&process, &QProcess::started, this, [this]
  {
#ifdef Q_OS_WIN
    const HANDLE child = OpenProcess (PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, DWORD (process.processId ()));
    if (child)
    {
      if (job_handle) AssignProcessToJobObject (job_handle, child);
      CloseHandle (child);
    }
#else
    if (slave_fd >= 0) { close (slave_fd); slave_fd = -1; }
#endif
    emit started ();
  });
  connect (&process, &QProcess::errorOccurred, this, [this] (QProcess::ProcessError error)
  {
    emit line (process.errorString ());
    if ((error == QProcess::FailedToStart) && (emitted == false))
    {
      emitted = true;
      deadline.stop ();
      release_input ();
      emit finished (-1, true);
    }
  });
  connect (&process, qOverload<int, QProcess::ExitStatus> (&QProcess::finished), this, [this] (int code, QProcess::ExitStatus status)
  {
    deadline.stop ();
    drain ();
    consume ({}, true);
    release_input ();
    if (emitted == false)
    {
      emitted = true;
      emit finished (code, status == QProcess::CrashExit);
    }
  });
}

Runner::~Runner ()
{
  process.disconnect (this);
  if (busy ()) { process.kill (); process.waitForFinished (3000); }
  release_input ();
}

bool Runner::busy () const
{
  return process.state () != QProcess::NotRunning;
}

bool Runner::start (const QString &binary, const QStringList &args, const QString &cwd, const bool interactive)
{
  if (busy ()) return false;
  release_input ();
  pending.clear ();
  emitted = false;
  accepting_commands = interactive;
#ifdef Q_OS_WIN
  if (interactive)
  {
    if (GetConsoleWindow () == nullptr)
    {
      if (AllocConsole ()) ShowWindow (GetConsoleWindow (), SW_HIDE);
    }
    SECURITY_ATTRIBUTES attributes {sizeof (SECURITY_ATTRIBUTES), nullptr, TRUE};
    input = CreateFileW (L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr);
    if (input == INVALID_HANDLE_VALUE) input = nullptr;
    if (input == nullptr)
    {
      emit line (t ("Cannot open console input for Hashcat.", "Не удалось открыть консольный ввод Hashcat."));
      return false;
    }
    FlushConsoleInputBuffer (input);
  }
  job_handle = CreateJobObjectW (nullptr, nullptr);
  if (job_handle)
  {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject (job_handle, JobObjectExtendedLimitInformation, &limits, sizeof (limits));
  }
  process.setCreateProcessArgumentsModifier ([this, interactive] (QProcess::CreateProcessArguments *data)
  {
    if (interactive)
    {
      data->flags &= ~(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_CONSOLE);
      data->flags |= CREATE_NEW_PROCESS_GROUP;
      data->startupInfo->hStdInput = input;
      data->startupInfo->dwFlags |= STARTF_USESTDHANDLES;
      data->inheritHandles = TRUE;
    }
  });
#else
  process.setChildProcessModifier ({});
  if (interactive)
  {
    master_fd = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
    if ((master_fd < 0) || (grantpt (master_fd) != 0) || (unlockpt (master_fd) != 0))
    {
      release_input ();
      emit line (t ("Cannot create terminal input.", "Не удалось создать терминал."));
      return false;
    }
    slave_fd = open (ptsname (master_fd), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave_fd < 0) { release_input (); return false; }
    const int slave = slave_fd;
    process.setChildProcessModifier ([slave] { dup2 (slave, STDIN_FILENO); });
  }
#endif
  process.setWorkingDirectory (cwd);
  process.start (binary, args);
  return true;
}

void Runner::release_input ()
{
  accepting_commands = false;
#ifdef Q_OS_WIN
  if (input) { CloseHandle (input); input = nullptr; }
  if (job_handle) { CloseHandle (job_handle); job_handle = nullptr; }
#else
  if (master_fd >= 0) { close (master_fd); master_fd = -1; }
  if (slave_fd >= 0) { close (slave_fd); slave_fd = -1; }
#endif
}

bool Runner::command (const char key)
{
  if ((busy () == false) || (accepting_commands == false)) return false;
#ifdef Q_OS_WIN
  if (input == nullptr) return false;
  INPUT_RECORD record {};
  record.EventType = KEY_EVENT;
  record.Event.KeyEvent.bKeyDown = TRUE;
  record.Event.KeyEvent.wRepeatCount = 1;
  record.Event.KeyEvent.wVirtualKeyCode = WORD (VkKeyScanA (key) & 0xff);
  record.Event.KeyEvent.uChar.UnicodeChar = wchar_t (key);
  DWORD written = 0;
  return WriteConsoleInputW (input, &record, 1, &written) && (written == 1);
#else
  return (master_fd >= 0) && (write (master_fd, &key, 1) == 1);
#endif
}

void Runner::stop ()
{
  if (busy () == false) return;
  command ('q');
  emit line (t ("Stopping; the process will be terminated in 8 seconds if it does not respond.", "Остановка; если процесс не ответит, через 8 секунд он будет завершён принудительно."));
  deadline.start (8000);
}

void Runner::kill ()
{
  deadline.stop ();
  if (busy ()) process.kill ();
}

void Runner::drain ()
{
  consume (process.readAllStandardOutput ());
}

void Runner::consume (const QByteArray &bytes, const bool final)
{
  pending += bytes;
  qsizetype end = 0;
  while ((end = pending.indexOf ('\n')) >= 0)
  {
    QByteArray row = pending.left (end).trimmed ();
    pending.remove (0, end + 1);
    const qsizetype begin = row.indexOf ('{');
    if (begin >= 0)
    {
      const QJsonDocument doc = QJsonDocument::fromJson (row.mid (begin));
      const QJsonObject obj = doc.object ();
      if (obj.contains ("status") && obj.contains ("progress")) { emit status (obj); continue; }
    }
    if (row.isEmpty () == false)
    {
      QString text = QString::fromUtf8 (row);
      text.remove (QRegularExpression ("\\x1b\\[[0-9;?]*[ -/]*[@-~]"));
      emit line (text.left (16384));
    }
  }
  if ((pending.size () > 1024 * 1024) || (final && (pending.isEmpty () == false)))
  {
    emit line (QString::fromUtf8 (pending.left (16384)));
    pending.clear ();
  }
}
