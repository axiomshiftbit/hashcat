// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QObject>
#include <QProcess>
#include <QTimer>
#include <QTemporaryDir>
#include <QJsonObject>
#include <memory>

struct Extraction
{
  QString input, output, tool, interpreter, hashcat;
  QStringList arguments;
};

class Extractor : public QObject
{
  Q_OBJECT
public:
  explicit Extractor (QObject *parent = nullptr);
  ~Extractor () override;
  bool start (const Extraction &request);
  bool busy () const { return active; }
  void cancel ();
  static QJsonObject catalog ();
  static QByteArray normalize (const QByteArray &output);
signals:
  void log (const QString &message);
  void finished (bool success, const QString &path, const QList<int> &modes);
private:
  void drain ();
  void complete (bool success, const QList<int> &modes = {});
  Extraction config;
  QProcess process;
  QTimer timeout;
  std::unique_ptr<QTemporaryDir> temporary;
  QByteArray buffer, hashes;
  bool active = false, identifying = false, canceled = false;
};
