/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "converter.h"
#include "lang.h"
#include "bundled_tools.h"

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QTemporaryFile>
#include <QStandardPaths>

Converter::Converter (QObject *parent) : QObject (parent)
{
  connect (&process, &QProcess::readyReadStandardOutput, this, &Converter::drain);
  connect (&process, &QProcess::readyReadStandardError, this, [this]
  {
    emit log (QString::fromUtf8 (process.readAllStandardError ()).left (16384));
  });
  connect (&process, &QProcess::errorOccurred, this, [this] (QProcess::ProcessError error)
  {
    if (error == QProcess::FailedToStart)
    {
      emit log (process.errorString ());
      complete (false);
    }
  });
  connect (&process, qOverload<int, QProcess::ExitStatus> (&QProcess::finished), this, [this] (int code, QProcess::ExitStatus status)
  {
    drain ();
    if (canceled || (code != 0) || (status != QProcess::NormalExit)) { complete (false); return; }
    if (path_step > 0)
    {
      const QString path = QString::fromUtf8 (path_buffer).trimmed ();
      path_buffer.clear ();
      if (path.startsWith ('/') == false) { complete (false); return; }
      if (path_step == 1)
      {
        source_path = path;
        path_step = 2;
        process.start ("wsl.exe", {"--exec", "wslpath", "-u", QDir::toNativeSeparators (temporary->path ())});
        return;
      }
      work_path = path;
      path_step = 0;
    }
    next ();
  });
}

Converter::~Converter ()
{
  process.disconnect (this);
  if (process.state () != QProcess::NotRunning) { process.kill (); process.waitForFinished (3000); }
}

bool Converter::busy () const { return active; }

QString Converter::tool (const QString &name) const
{
  if (config.wsl) return name;
  if (config.tools_directory.isEmpty ()) return QStandardPaths::findExecutable (name);
#ifdef Q_OS_WIN
  return QDir (config.tools_directory).filePath (name + ".exe");
#else
  return QDir (config.tools_directory).filePath (name);
#endif
}

bool Converter::start (const Conversion &request)
{
  if (active) return false;
  config = request;
  const QFileInfo input (config.input);
  if ((input.isFile () == false) || (input.isReadable () == false) || QFileInfo::exists (config.output))
  {
    emit log (t ("Choose a readable input and a NEW output file.", "Выберите доступный исходный файл и НОВЫЙ файл результата."));
    return false;
  }
  if (QList<int> {22000, 4800, 5500, 16100}.contains (config.mode) == false) return false;
  temporary = std::make_unique<QTemporaryDir> (QDir::tempPath () + "/hashcat-convert-XXXXXX");
  if (temporary->isValid () == false) return false;
  QFile::setPermissions (temporary->path (), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
  source_path = input.absoluteFilePath ();
  work_path = temporary->path ();
  steps.clear ();
  canceled = false;
  active = true;
  path_step = config.wsl ? 1 : 0;
  path_buffer.clear ();
  process.setProcessEnvironment (QProcessEnvironment::systemEnvironment ());
  if (config.wsl)
  {
    process.start ("wsl.exe", {"--exec", "wslpath", "-u", QDir::toNativeSeparators (source_path)});
    return true;
  }
  next ();
  return true;
}

void Converter::next ()
{
  if ((steps.isEmpty () == false) && steps.first ().first.isEmpty ()) { complete (true); return; }
  if (steps.isEmpty ())
  {
    if (QFileInfo::exists (temporary->filePath ("output.hashes"))) { complete (true); return; }
    const QString suffix = QFileInfo (config.input).suffix ().toLower ();
    QString legacy;
    if (suffix == "hccapx") legacy = "--hccapx=";
    if (suffix == "hccap") legacy = "--hccap=";
    if ((suffix == "16800") || (suffix == "pmkid")) legacy = "--pmkid=";
    if (legacy.isEmpty () == false)
    {
      steps.append ({"hcxhash2cap", {legacy + source_path, "-c", work_path + "/legacy.cap"}});
      source_path = work_path + "/legacy.cap";
    }
    const QMap<int, QString> option {{22000, "-o"}, {4800, "--eapmd5"}, {5500, "--eapleap"}, {16100, "--tacacs-plus"}};
    steps.append ({"hcxpcapngtool", {option.value (config.mode), work_path + "/output.hashes", source_path}});
  }
  const auto step = steps.takeFirst ();
  const QString binary = tool (step.first);
  if (binary.isEmpty ())
  {
    emit log (t ("hcxtools not found. Select its directory or install hcxtools.", "hcxtools не найден. Укажите его каталог или установите hcxtools."));
    complete (false);
    return;
  }
  emit log (t ("Running ", "Выполняется ") + step.first);
  if (config.wsl) process.start ("wsl.exe", QStringList {"--exec", binary} + step.second);
  else
  {
    process.setProcessEnvironment (tool_environment (binary));
    process.start (binary, step.second);
  }
  // An empty output must finish this pipeline, rather than start it again.
  if (steps.isEmpty ()) steps.append ({QString (), {}});
}

void Converter::drain ()
{
  const QByteArray data = process.readAllStandardOutput ();
  if (path_step > 0) path_buffer += data.left (8192);
  else if (data.isEmpty () == false) emit log (QString::fromUtf8 (data).left (16384));
}

void Converter::complete (bool success)
{
  if (active == false) return;
  int count = 0;
  if (success)
  {
    QFile input (temporary->filePath ("output.hashes"));
    QTemporaryFile output (config.output + ".XXXXXX");
    if (QFileInfo::exists (config.output) || (input.open (QIODevice::ReadOnly) == false) || (input.size () == 0)) success = false;
    if (success && (output.open () == false)) success = false;
    if (success)
    {
      output.setPermissions (QFileDevice::ReadOwner | QFileDevice::WriteOwner);
      while (input.atEnd () == false)
      {
        const QByteArray chunk = input.read (65536);
        if (chunk.isEmpty ()) { success = false; break; }
        count += chunk.count ('\n');
        if (output.write (chunk) != chunk.size ()) { success = false; break; }
      }
      if (success) success = output.flush () && output.rename (config.output);
      if (success) output.setAutoRemove (false);
    }
  }
  if (success == false) emit log (t ("No hashes saved. The capture may contain no complete matching exchange, or a dependency failed.", "Хеши не сохранены. В захвате может не быть подходящего полного обмена, либо недоступна зависимость."));
  active = false;
  steps.clear ();
  temporary.reset ();
  emit finished (success, config.output, count);
}

void Converter::cancel ()
{
  if (active == false) return;
  canceled = true;
  if (process.state () != QProcess::NotRunning) process.kill ();
  else complete (false);
}
