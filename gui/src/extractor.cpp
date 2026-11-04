// SPDX-License-Identifier: GPL-3.0-or-later
// Catalog and marker cleanup adapted from Hashcat-Reactor (c) 2025 rabbit (MIT).
// Tools remain separate dependencies. Results require Hashcat identification.
#include "extractor.h"
#include "lang.h"
#include "bundled_tools.h"
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QTemporaryFile>
#include <QStandardPaths>
#include <QSet>

static void init_catalog () { Q_INIT_RESOURCE (extractor_registry); }

QJsonObject Extractor::catalog ()
{
  init_catalog ();
  QFile file (":/third_party/hashcat_reactor/tool_registry.json");
  if (!file.open (QIODevice::ReadOnly)) return {};
  return QJsonDocument::fromJson (file.readAll ()).object ();
}

QByteArray Extractor::normalize (const QByteArray &output)
{
  QByteArray result; QSet<QByteArray> seen;
  for (auto line : output.split ('\n'))
  {
    line = line.trimmed ();
    const auto match = QRegularExpression ("(?:^|:)(\\$[A-Za-z0-9_-]+\\$)").match (QString::fromUtf8 (line));
    if (!match.hasMatch ()) continue;
    const int marker = int (QString::fromUtf8 (line).left (match.capturedStart (1)).toUtf8 ().size ());
    // John prefixes a filename and can append colon-separated metadata.
    // Preserve case: signatures such as $RAR3$ are case-sensitive.
    line = line.mid (marker);
    const int trailer = line.indexOf (':');
    if (trailer >= 0) line.truncate (trailer);
    if (line.startsWith ("$pdf$"))
    {
      auto fields = line.split ('*');
      if (fields.size () > 3)
      {
        bool ok = false;
        const quint64 permissions = fields[3].toULongLong (&ok);
        // Preserve PDF's 32 permission bits without overflowing Windows strtol.
        if (ok && permissions >= 0x80000000ULL && permissions <= 0xffffffffULL)
        {
          fields[3] = QByteArray::number (qint64 (permissions) - 0x100000000LL);
          line = fields.join ('*');
        }
      }
    }
    if (!line.contains (QChar (0).toLatin1 ()) && !seen.contains (line)) { seen.insert (line); result += line + '\n'; }
  }
  return result;
}

Extractor::Extractor (QObject *parent) : QObject (parent)
{
  timeout.setSingleShot (true);
  connect (&timeout, &QTimer::timeout, this, [this] { emit log (t ("Extractor timed out.", "Истекло время извлечения.")); cancel (); });
  connect (&process, &QProcess::readyReadStandardOutput, this, &Extractor::drain);
  connect (&process, &QProcess::readyReadStandardError, this, [this] { emit log (QString::fromUtf8 (process.readAllStandardError ()).left (16384)); });
  connect (&process, &QProcess::errorOccurred, this, [this] (QProcess::ProcessError error)
  {
    if (error == QProcess::FailedToStart) { emit log (process.errorString ()); complete (false); }
  });
  connect (&process, qOverload<int, QProcess::ExitStatus> (&QProcess::finished), this, [this] (int code, QProcess::ExitStatus status)
  {
    drain ();
    if (canceled || status != QProcess::NormalExit || code != 0) { complete (false); return; }
    if (!identifying)
    {
      hashes = normalize (buffer); buffer.clear ();
      if (hashes.isEmpty ()) { emit log (t ("No supported hash records in extractor output.", "В выводе не найдено поддерживаемых записей хешей.")); complete (false); return; }
      QFile file (temporary->filePath ("input.hashes"));
      if (!file.open (QIODevice::WriteOnly) || file.write (hashes) != hashes.size ()) { complete (false); return; }
      file.setPermissions (QFileDevice::ReadOwner | QFileDevice::WriteOwner); file.close ();
      identifying = true;
      emit log (t ("Checking compatibility with the selected Hashcat…", "Проверка совместимости с выбранным Hashcat…"));
      process.setWorkingDirectory (QFileInfo (config.hashcat).absolutePath ());
      process.setProcessEnvironment (QProcessEnvironment::systemEnvironment ());
      process.start (config.hashcat, {"--quiet", "--identify", "--machine-readable", temporary->filePath ("input.hashes")});
      timeout.start (180000);
      return;
    }
    QList<int> modes;
    const QRegularExpression numeric ("^[0-9]{1,6}$");
    for (const auto &line : QString::fromUtf8 (buffer).split ('\n'))
    {
      const QString value = line.trimmed ();
      if (numeric.match (value).hasMatch () && !modes.contains (value.toInt ())) modes << value.toInt ();
    }
    if (modes.isEmpty ()) emit log (t ("The installed Hashcat did not recognize this format. John-only formats cannot be imported.", "Установленный Hashcat не распознал формат. Форматы только для John импортировать нельзя."));
    complete (!modes.isEmpty (), modes);
  });
}

Extractor::~Extractor ()
{
  process.disconnect (this);
  if (process.state () != QProcess::NotRunning) { process.kill (); process.waitForFinished (3000); }
}

bool Extractor::start (const Extraction &request)
{
  if (active) return false;
  if (!QFileInfo (request.input).isFile () || !QFileInfo (request.tool).isFile () || !QFileInfo (request.hashcat).isExecutable () || QFileInfo::exists (request.output))
  {
    emit log (t ("Select an input, extractor, Hashcat and NEW output file.", "Укажите исходный файл, конвертер, Hashcat и НОВЫЙ файл результата.")); return false;
  }
  config = request;
  config.input = QFileInfo (config.input).absoluteFilePath (); config.tool = QFileInfo (config.tool).absoluteFilePath ();
  config.hashcat = QFileInfo (config.hashcat).absoluteFilePath (); config.output = QFileInfo (config.output).absoluteFilePath ();
  temporary = std::make_unique<QTemporaryDir> (QDir::tempPath () + "/hashcat-extract-XXXXXX");
  if (!temporary->isValid ()) return false;
  QFile::setPermissions (temporary->path (), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
  QString program = config.tool; QStringList args = config.arguments;
  const QString suffix = QFileInfo (program).suffix ().toLower ();
  if (suffix == "py" || suffix == "pl")
  {
    args.prepend (program);
    program = config.interpreter;
    if (program.isEmpty ()) program = bundled_interpreter (suffix, config.tool);
    if (program.isEmpty ()) program = QStandardPaths::findExecutable (suffix == "pl" ? "perl" : "python3");
    if (program.isEmpty () && suffix == "py") program = QStandardPaths::findExecutable ("python");
    if (program.isEmpty ()) { emit log (t ("Install/select the Python or Perl interpreter required by this tool.", "Установите/выберите нужный конвертеру Python или Perl.")); return false; }
    if (program == bundled_tool ("python/python.exe")) args = QStringList {"-X", "utf8"} + args;
  }
  args << config.input;
  buffer.clear (); hashes.clear (); active = true; canceled = false; identifying = false;
  process.setWorkingDirectory (QFileInfo (config.tool).absolutePath ());
  process.setProcessEnvironment (tool_environment (program));
  process.start (program, args); timeout.start (180000);
  return true;
}

void Extractor::drain ()
{
  buffer += process.readAllStandardOutput ();
  if (buffer.size () > 64 * 1024 * 1024)
  {
    buffer.clear (); emit log (t ("Extractor output exceeds 64 MiB.", "Вывод конвертера превысил 64 МиБ.")); cancel ();
  }
}

void Extractor::cancel () { if (active) { canceled = true; process.kill (); } }

void Extractor::complete (bool success, const QList<int> &modes)
{
  if (!active) return;
  timeout.stop ();
  if (success)
  {
    QTemporaryFile out (config.output + ".XXXXXX");
    success = !QFileInfo::exists (config.output) && out.open ();
    if (success)
    {
      out.setPermissions (QFileDevice::ReadOwner | QFileDevice::WriteOwner);
      success = out.write (hashes) == hashes.size () && out.flush () && out.rename (config.output);
      if (success) out.setAutoRemove (false);
    }
  }
  if (!success) emit log (t ("Extraction failed or format is incompatible. No output file was saved.", "Извлечение не удалось или формат несовместим. Файл результата не сохранён."));
  active = false; temporary.reset (); buffer.clear (); hashes.clear ();
  emit finished (success, success ? config.output : QString (), success ? modes : QList<int> {});
}
