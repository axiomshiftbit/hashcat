// SPDX-License-Identifier: GPL-3.0-or-later
#include "bundled_tools.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

QString bundled_tool (const QString &relative)
{
  const QString path = QDir (QCoreApplication::applicationDirPath ()).filePath ("tools/" + relative);
  return QFileInfo::exists (path) ? path : QString ();
}

QString bundled_interpreter (const QString &suffix, const QString &tool)
{
  const QString name = QFileInfo (tool).fileName ().toLower ();
  if (name == "pdf2john.py" || name == "krb2john.py") return bundled_tool ("python/python.exe");
  if (suffix == "py") return bundled_tool ("cygwin/bin/python3.12.exe");
  if (suffix == "pl") return bundled_tool ("cygwin/bin/perl.exe");
  return {};
}

QString tool_input_path (const QString &program, const QString &path)
{
#ifdef Q_OS_WIN
  if (!program.isEmpty () && (program == bundled_interpreter ("py") || program == bundled_interpreter ("pl")))
  {
    const QString normalized = QDir::fromNativeSeparators (path);
    if (normalized.size () >= 3 && normalized[1] == ':' && normalized[2] == '/')
      return "/cygdrive/" + normalized.left (1).toLower () + normalized.mid (2);
    return normalized;
  }
#else
  Q_UNUSED (program);
#endif
  return path;
}

QProcessEnvironment tool_environment (const QString &program)
{
  QProcessEnvironment environment = QProcessEnvironment::systemEnvironment ();
#ifdef Q_OS_WIN
  const QString root = QDir (QCoreApplication::applicationDirPath ()).filePath ("tools/");
  if (QFileInfo (program).absoluteFilePath ().startsWith (root, Qt::CaseInsensitive))
  {
    const QString runtime = bundled_tool ("cygwin/bin");
    const QString john = bundled_tool ("john/run");
    environment.insert ("PATH", QDir::toNativeSeparators (runtime) + ';' + QDir::toNativeSeparators (john) + ';' + environment.value ("PATH"));
    for (const char *name : {"PYTHONHOME", "PYTHONPATH", "PERL5LIB", "OPENSSL_CONF", "OPENSSL_MODULES"}) environment.remove (name);
    environment.insert ("LC_ALL", "C.UTF-8");
    environment.insert ("PYTHONUTF8", "1");
    environment.insert ("PYTHONNOUSERSITE", "1");
    environment.insert ("PYTHONDONTWRITEBYTECODE", "1");
    environment.insert ("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python");
  }
#else
  Q_UNUSED (program);
#endif
  return environment;
}
