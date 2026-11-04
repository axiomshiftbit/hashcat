/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#pragma once

#include <QObject>
#include <QProcess>
#include "managed_process.h"
#include <QTemporaryDir>
#include <memory>

struct Conversion
{
  QString input, output, tools_directory;
  int mode = 22000;
  bool wsl = false;
};

class Converter : public QObject
{
  Q_OBJECT
public:
  explicit Converter (QObject *parent = nullptr);
  ~Converter () override;
  bool start (const Conversion &request);
  bool busy () const;
  void cancel ();
signals:
  void log (const QString &text);
  void finished (bool success, const QString &path, int count);
private:
  void next ();
  void complete (bool success);
  void drain ();
  QString tool (const QString &name) const;
  Conversion config;
  ManagedProcess process;
  std::unique_ptr<QTemporaryDir> temporary;
  QList<QPair<QString, QStringList>> steps;
  QString source_path, work_path;
  int path_step = 0;
  bool active = false, canceled = false;
  QByteArray path_buffer;
};
