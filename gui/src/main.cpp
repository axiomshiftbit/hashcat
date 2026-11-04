/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "window.h"

#include <QApplication>
#include <QDir>
#include <QLockFile>
#include <QMessageBox>
#include <QStandardPaths>

int main (int argc, char **argv)
{
  QApplication app (argc, argv);
  app.setApplicationName ("Hashcat Desktop");
  app.setOrganizationName ("HashcatDesktop");
  app.setApplicationVersion ("0.1.0");
  app.setStyle ("Fusion");
  QString root = QStandardPaths::writableLocation (QStandardPaths::AppLocalDataLocation);
  const QStringList args = app.arguments ();
  const int index = args.indexOf ("--data-dir");
  if ((index >= 0) && (index + 1 < args.size ())) root = QFileInfo (args[index + 1]).absoluteFilePath ();
  QDir ().mkpath (root);
  QFile::setPermissions (root, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
  QLockFile lock (QDir (root).filePath ("desktop.lock"));
  if (lock.tryLock (100) == false)
  {
    QMessageBox::warning (nullptr, "Hashcat Desktop", "The application is already running / Приложение уже запущено");
    return 1;
  }
  Window window (root);
  window.show ();
  return app.exec ();
}
