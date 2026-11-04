/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QThread>
#include <cstdio>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

int main (int argc, char **argv)
{
  QCoreApplication app (argc, argv);
  const QStringList args = app.arguments ();
  if (args.contains ("--version")) { puts ("v8.0.0-fixture"); return 0; }
  if (args.contains ("-hh")) { puts ("--restore-position\n0 | MD5 | Raw Hash\n22000 | WPA-PBKDF2-PMKID+EAPOL | Network Protocol"); return 0; }
  if (args.contains ("--fixture-arguments"))
  {
    puts (QJsonDocument (QJsonArray::fromStringList (args.mid (1))).toJson (QJsonDocument::Compact).constData ());
    return 0;
  }
  if (args.contains ("--fixture-stdin"))
  {
    QFile input;
    if (input.open (stdin, QIODevice::ReadOnly) == false) return 1;
    puts (input.readAll ().toBase64 ().constData ());
    return 0;
  }
  const bool wait = args.contains ("--fixture-wait");
  const bool failure = args.contains ("--fixture-failure");
  const bool exhausted = args.contains ("--fixture-exhausted");
  QString outfile;
  for (const QString &arg : args) if (arg.startsWith ("--outfile=")) outfile = arg.mid (10);
#ifndef Q_OS_WIN
  termios original {};
  const bool terminal = tcgetattr (STDIN_FILENO, &original) == 0;
  if (terminal)
  {
    termios raw = original; raw.c_lflag &= ~(ICANON | ECHO); raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
    tcsetattr (STDIN_FILENO, TCSANOW, &raw);
  }
#else
  DWORD console_mode = 0;
  const bool terminal = GetConsoleMode (GetStdHandle (STD_INPUT_HANDLE), &console_mode);
#endif
  puts (terminal ? "TERMINAL_READY" : "NO_TERMINAL"); fflush (stdout);
  bool paused = false;
  for (int tick = 0; (tick < 5) || wait; ++tick)
  {
    char key = 0;
#ifdef Q_OS_WIN
    DWORD count = 0;
    if (GetNumberOfConsoleInputEvents (GetStdHandle (STD_INPUT_HANDLE), &count) && (count > 0))
    {
      INPUT_RECORD record {}; DWORD read = 0;
      ReadConsoleInputW (GetStdHandle (STD_INPUT_HANDLE), &record, 1, &read);
      if ((record.EventType == KEY_EVENT) && record.Event.KeyEvent.bKeyDown) key = char (record.Event.KeyEvent.uChar.UnicodeChar);
    }
#else
    fd_set set; FD_ZERO (&set); FD_SET (STDIN_FILENO, &set);
    timeval timeout {0, 0};
    if (select (STDIN_FILENO + 1, &set, nullptr, nullptr, &timeout) > 0)
    {
      const auto count = read (STDIN_FILENO, &key, 1); Q_UNUSED (count);
    }
#endif
    if ((key == 'q') || (key == 'c')) return key == 'c' ? 3 : 2;
    if (key == 'p') paused = true;
    if (key == 'r') paused = false;
    printf ("{\"session\":\"fixture\",\"status\":%d,", paused ? 4 : 3); fflush (stdout);
    QThread::msleep (5);
    printf ("\"progress\":[%d,100],\"recovered_hashes\":[0,1],\"devices\":[{\"device_id\":1,\"device_name\":\"Test CPU\",\"speed\":1200}],\"estimated_stop\":1}\n", tick % 100); fflush (stdout);
    QThread::msleep (100);
  }
  if (failure) { fputs ("Fixture error\n", stderr); return 255; }
  if (exhausted) return 1;
  if (outfile.isEmpty () == false)
  {
    QFile file (outfile);
    if (file.open (QIODevice::WriteOnly)) file.write ("synthetic:73616d706c65\n");
  }
  fputs ("Completed without trailing newline", stdout);
  return 0;
}
