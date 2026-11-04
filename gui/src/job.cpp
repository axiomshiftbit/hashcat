/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "job.h"
#include "lang.h"

#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>

QString Job::directory (const QString &root) const
{
  return QDir (root).filePath ("jobs/" + id);
}

QString Job::validate () const
{
  const QRegularExpression identifier ("^[a-zA-Z0-9_-]{1,64}$");
  if (identifier.match (id).hasMatch () == false) return t ("Invalid session identifier.", "Неверный идентификатор сессии.");
  if (name.trimmed ().isEmpty ()) return t ("Enter a task name.", "Укажите название задачи.");
  if ((QFileInfo (binary).isFile () == false) || (QFileInfo (binary).isExecutable () == false)) return t ("Select the Hashcat executable.", "Выберите исполняемый файл Hashcat.");
  const auto readable = [] (const QString &path)
  {
    const QFileInfo info (path);
    return info.isFile () && info.isReadable ();
  };
  if (readable (hashes) == false) return t ("Hash file is missing or unreadable.", "Файл хешей не найден или недоступен для чтения.");
  if (QSet<int> {0, 1, 3, 6, 7, 9}.contains (attack) == false) return t ("This attack is not supported by the form. Use Commands.", "Режим атаки не поддерживается формой.");
  if ((attack != 3) && (readable (dictionary) == false)) return t ("Select a readable dictionary.", "Выберите доступный словарь.");
  if ((attack == 1) && (readable (dictionary2) == false)) return t ("Combinator mode needs a second dictionary.", "Для комбинации нужен второй словарь.");
  if ((attack == 3) || (attack == 6) || (attack == 7))
  {
    if (mask.isEmpty ()) return t ("Enter a mask or a .hcmask file.", "Укажите маску или файл .hcmask.");
    if (mask.startsWith ('-')) return t ("A mask cannot start with a dash. Use a .hcmask file.", "Маска не должна начинаться с дефиса. Используйте файл .hcmask.");
    if (mask.endsWith (".hcmask", Qt::CaseInsensitive) && (readable (mask) == false)) return t ("Mask file not found.", "Файл масок не найден.");
    if (mask.contains ('\n') || mask.contains ('\r') || mask.contains (QChar (0))) return t ("The mask must be a single line.", "Маска должна занимать одну строку.");
    if (QFileInfo (mask).isFile () == false)
    {
      for (qsizetype i = 0; i < mask.size (); ++i)
      {
        if (mask[i] != '?') continue;
        ++i;
        if ((i == mask.size ()) || (QString ("ludhHsab1234?").contains (mask[i]) == false)) return t ("Invalid mask token after ?.", "Неверный символ маски после ?.");
        const int charset = mask[i].digitValue ();
        if ((charset >= 1) && (charset <= 4) && charsets[charset - 1].isEmpty ()) return t ("Define the custom character set used by the mask.", "Задайте пользовательский набор символов для маски.");
      }
    }
  }
  if ((hash_mode < 0) || (hash_mode > 999999)) return t ("Invalid hash mode number.", "Неверный номер типа хеша.");
  if ((workload < 1) || (workload > 4)) return t ("Invalid workload profile.", "Неверный профиль нагрузки.");
  if ((device_type < 0) || (device_type > 3)) return t ("Invalid device type.", "Неверный тип устройства.");
  if ((temperature < 50) || (temperature > 100) || (runtime < 0)) return t ("Check temperature and time limits.", "Проверьте лимиты температуры и времени.");
  if (increment && ((minimum < 1) || (maximum < minimum) || (maximum > 256))) return t ("Check the mask length range.", "Проверьте диапазон длины маски.");
  if (devices.isEmpty () == false)
  {
    if (QRegularExpression ("^[1-9][0-9]*(,[1-9][0-9]*)*$").match (devices).hasMatch () == false) return t ("Devices: comma-separated IDs, for example 1,2.", "Устройства: номера через запятую, например 1,2.");
  }
  for (const QString &rule : rules)
  {
    if (readable (rule) == false) return t ("A rule file is not readable.", "Один из файлов правил недоступен.");
  }
  const QSet<QString> flags {"--hex-salt", "--hex-charset", "--hex-wordlist", "--markov-disable", "--slow-candidates", "--keep-guessing", "--deprecated-check-disable"};
  const QSet<QString> values {"--encoding-from", "--encoding-to", "--kernel-accel", "--kernel-loops", "--kernel-threads", "--skip", "--limit", "--markov-threshold", "--hash-recipe"};
  for (const QString &arg : extra)
  {
    if (flags.contains (arg)) continue;
    const qsizetype eq = arg.indexOf ('=');
    if ((eq > 0) && values.contains (arg.left (eq)) && (eq + 1 < arg.size ()) && (arg.contains ('\n') == false) && (arg.contains (QChar (0)) == false)) continue;
    return t ("Use the Commands page for this additional option: ", "Дополнительный параметр не поддерживается: ") + arg;
  }
  return {};
}

QStringList Job::arguments (const QString &root, const bool restore, const bool modern) const
{
  const QString dir = directory (root);
  if (restore && (modern == false)) return {"--session=" + id, "--restore-file-path=" + dir + "/session.restore", "--restore"};
  QStringList args {"-m", QString::number (hash_mode), "-a", QString::number (attack),
    "--session=" + id, "--status", "--status-json", "--status-timer=1", "--restore-timer=1",
    "--restore-file-path=" + dir + "/session.restore", "--potfile-path=" + dir + "/hashcat.potfile",
    "--outfile=" + dir + "/results.txt", "--outfile-format=1,3", "--logfile-disable",
    "-w", QString::number (workload), "--hwmon-temp-abort=" + QString::number (temperature)};
  if (restore) args << "--restore-position";
  if (optimized) args << "-O";
  if (username) args << "--username";
  if (force) args << "--force";
  if (runtime > 0) args << "--runtime=" + QString::number (runtime);
  if (device_type > 0) args << "-D" << (device_type == 3 ? "1,2" : QString::number (device_type));
  if (devices.isEmpty () == false) args << "-d" << devices;
  if (increment && ((attack == 3) || (attack == 6) || (attack == 7))) args << "--increment" << "--increment-min=" + QString::number (minimum) << "--increment-max=" + QString::number (maximum);
  for (int i = 0; i < 4; ++i)
  {
    if (charsets[i].isEmpty () == false) args << "-" + QString::number (i + 1) << charsets[i];
  }
  for (const QString &rule : rules) args << "-r" << QFileInfo (rule).absoluteFilePath ();
  args << extra << QFileInfo (hashes).absoluteFilePath ();
  const QString actual_mask = QFileInfo (mask).isFile () ? QFileInfo (mask).absoluteFilePath () : mask;
  if (attack == 7) args << actual_mask;
  if (attack != 3) args << QFileInfo (dictionary).absoluteFilePath ();
  if (attack == 1) args << QFileInfo (dictionary2).absoluteFilePath ();
  if ((attack == 3) || (attack == 6)) args << actual_mask;
  return args;
}

QJsonObject Job::json () const
{
  QJsonObject obj;
  obj["id"] = id; obj["name"] = name; obj["binary"] = binary; obj["hashes"] = hashes;
  obj["dictionary"] = dictionary; obj["dictionary2"] = dictionary2; obj["mask"] = mask; obj["devices"] = devices;
  obj["rules"] = QJsonArray::fromStringList (rules); obj["extra"] = QJsonArray::fromStringList (extra);
  QJsonArray sets;
  for (const auto &charset : charsets) sets.append (charset);
  obj["charsets"] = sets;
  obj["hash_mode"] = hash_mode; obj["attack"] = attack; obj["workload"] = workload; obj["device_type"] = device_type;
  obj["temperature"] = temperature; obj["runtime"] = runtime; obj["minimum"] = minimum; obj["maximum"] = maximum;
  obj["increment"] = increment; obj["optimized"] = optimized; obj["username"] = username; obj["force"] = force; obj["state"] = state;
  return obj;
}

Job Job::from_json (const QJsonObject &obj)
{
  Job job;
  job.id = obj["id"].toString (); job.name = obj["name"].toString (); job.binary = obj["binary"].toString ();
  job.hashes = obj["hashes"].toString (); job.dictionary = obj["dictionary"].toString (); job.dictionary2 = obj["dictionary2"].toString ();
  job.mask = obj["mask"].toString (); job.devices = obj["devices"].toString ();
  for (const auto &rule : obj["rules"].toArray ()) job.rules << rule.toString ();
  for (const auto &arg : obj["extra"].toArray ()) job.extra << arg.toString ();
  const QJsonArray sets = obj["charsets"].toArray ();
  for (qsizetype i = 0; i < qMin<qsizetype> (4, sets.size ()); ++i) job.charsets[i] = sets[i].toString ();
  job.hash_mode = obj["hash_mode"].toInt (); job.attack = obj["attack"].toInt (); job.workload = obj["workload"].toInt (2);
  job.device_type = obj["device_type"].toInt (); job.temperature = obj["temperature"].toInt (85); job.runtime = obj["runtime"].toInt ();
  job.minimum = obj["minimum"].toInt (1); job.maximum = obj["maximum"].toInt (8);
  job.increment = obj["increment"].toBool (); job.optimized = obj["optimized"].toBool (); job.username = obj["username"].toBool ();
  job.force = obj["force"].toBool (); job.state = obj["state"].toString ("waiting");
  return job;
}

bool save_json (const QString &path, const QJsonObject &object, QString *error)
{
  QSaveFile file (path);
  if (file.open (QIODevice::WriteOnly) == false)
  {
    if (error) *error = file.errorString ();
    return false;
  }
  file.setPermissions (QFileDevice::ReadOwner | QFileDevice::WriteOwner);
  const QByteArray bytes = QJsonDocument (object).toJson ();
  if ((file.write (bytes) != bytes.size ()) || (file.commit () == false))
  {
    if (error) *error = file.errorString ();
    return false;
  }
  return true;
}

QString display_command (const QString &binary, const QStringList &arguments)
{
  QStringList parts {binary};
  parts << arguments;
  for (QString &part : parts)
  {
    part.replace ('\\', "\\\\"); part.replace ('"', "\\\"");
    part = '"' + part + '"';
  }
  return parts.join (' ');
}

QString state_text (const QString &state)
{
  const QMap<QString, QString> names {{"waiting", t ("Queued", "В очереди")}, {"running", t ("Running", "Выполняется")}, {"paused", t ("Paused", "Пауза")},
    {"completed", t ("Recovered", "Восстановлено")}, {"exhausted", t ("Exhausted", "Перебор завершён")}, {"failed", t ("Failed", "Ошибка")}, {"stopped", t ("Stopped", "Остановлено")}, {"interrupted", t ("Interrupted", "Прервано")}};
  return names.value (state, state);
}

QString exit_text (const int code)
{
  if (code == 0) return t ("All hashes recovered.", "Все хеши восстановлены.");
  if (code == 1) return t ("Candidates exhausted. Some hashes may remain unrecovered.", "Кандидаты закончились. Часть хешей могла остаться невосстановленной.");
  if (code == 2) return t ("Task stopped.", "Задача остановлена.");
  if (code == 3) return t ("Stopped at a checkpoint.", "Остановлено на контрольной точке.");
  if (code == 4) return t ("Time limit reached.", "Достигнут лимит времени.");
  return t ("Hashcat failed (exit code ", "Hashcat завершился с ошибкой (код ") + QString::number (code) + t ("). See the log for details.", "). Подробности в журнале.");
}

QString speed_text (double speed)
{
  const QStringList units {"H/s", "kH/s", "MH/s", "GH/s", "TH/s"};
  int index = 0;
  while ((speed >= 1000) && (index < units.size () - 1)) { speed /= 1000; ++index; }
  return QString::number (speed, 'f', 2) + ' ' + units[index];
}

QList<QPair<int, QString>> parse_modes (const QByteArray &help)
{
  QList<QPair<int, QString>> result;
  const QRegularExpression row ("^\\s*([0-9]+)\\s*\\|\\s*([^|]+)\\|");
  for (const QString &line : QString::fromUtf8 (help).split ('\n'))
  {
    const auto match = row.match (line);
    if (match.hasMatch ()) result.append ({match.captured (1).toInt (), match.captured (2).trimmed ()});
  }
  return result;
}
