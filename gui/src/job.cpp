/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "job.h"
#include "lang.h"
#include "commandbuilder.h"
#include "helperutils.h"

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

HashcatOptions Job::command_options () const
{
  HashcatOptions o;
  o.useShortParameters = true;
  o.hashType = hash_mode; o.attackMode = static_cast<AttackMode> (attack);
  o.hashFile = QFileInfo (hashes).absoluteFilePath ();
  o.force = force; o.optimizedKernel = optimized; o.ignoreUsername = username;
  o.runtime = runtime; o.backendDevices = devices;
  if (device_type > 0) o.openclDeviceTypes = device_type == 3 ? "1,2" : QString::number (device_type);
  o.hwmonTempAbort = true; o.hwmonTempAbortCelsius = temperature;
  o.increment = increment; o.incrementMin = minimum; o.incrementMax = maximum;
  o.mask = QFileInfo (mask).isFile () ? QFileInfo (mask).absoluteFilePath () : mask;
  o.wordlists = wordlists;
  if (o.wordlists.isEmpty ())
  {
    if (dictionary.isEmpty () == false) o.wordlists << dictionary;
    if ((attack == 1 || attack == 12) && (dictionary2.isEmpty () == false)) o.wordlists << dictionary2;
  }
  if (CommandBuilder::attackUsesWordlists (o.attackMode) == false) o.wordlists.clear ();
  for (QString &path : o.wordlists) path = QFileInfo (path).absoluteFilePath ();
  for (const QString &path : rules) o.rulesFiles << QFileInfo (path).absoluteFilePath ();
  for (int i = 0; i < 4; ++i)
  {
    o.customCharsets[i].enabled = charsets[i].isEmpty () == false;
    o.customCharsets[i].value = QFileInfo (charsets[i]).isFile () ? QFileInfo (charsets[i]).absoluteFilePath () : charsets[i];
  }
  const auto list = [this] (const char *key)
  {
    QStringList result;
    for (const QJsonValue &item : advanced[key].toArray ()) result << item.toString ();
    return result;
  };
  o.pcfgRulesets = list ("pcfgRulesets"); o.tableFiles = list ("tableFiles");
  o.feedName = advanced["feedName"].toString (); o.feedArguments = list ("feedArguments");
  o.associationSettings = list ("associationSettings");
  o.pcfgExtraSettings = list ("pcfgExtraSettings"); o.tableExtraSettings = list ("tableExtraSettings");
  o.pcfgScale = advanced["pcfgScale"].toString (); o.pcfgCostmax = advanced["pcfgCostmax"].toString ();
  o.pcfgWeights = advanced["pcfgWeights"].toString (); o.pcfgThreads = advanced["pcfgThreads"].toString ();
  o.pcfgKbits = advanced["pcfgKbits"].toString (); o.pcfgMaxword = advanced["pcfgMaxword"].toString ();
  o.pcfgMaxgain = advanced["pcfgMaxgain"].toString (); o.pcfgWalk = advanced["pcfgWalk"].toString ();
  o.pcfgMask = advanced["pcfgMask"].toString ();
  o.tableIdentity = advanced["tableIdentity"].toString (); o.tableTemplate = advanced["tableTemplate"].toString ();
  o.tableSingle = advanced["tableSingle"].toString (); o.tableCap = advanced["tableCap"].toString ();
  o.tableMaxperm = advanced["tableMaxperm"].toString ();
  o.ruleLeft = advanced["ruleLeft"].toString (); o.ruleRight = advanced["ruleRight"].toString ();
  o.generateRules = advanced["generateRules"].toInt (); o.rulesConcat = advanced["rulesConcat"].toBool ();
  o.hexWordlist = advanced["hexWordlist"].toBool (); o.hexCharset = advanced["hexCharset"].toBool ();
  o.hexSalt = advanced["hexSalt"].toBool (); o.encodingFrom = advanced["encodingFrom"].toString ();
  o.encodingTo = advanced["encodingTo"].toString (); o.hashRecipe = advanced["hashRecipe"].toString ();
  o.skip = advanced["skip"].toString (); o.limit = advanced["limit"].toString ();
  o.cpuAffinity = advanced["cpuAffinity"].toString (); o.cachePath = advanced["cachePath"].toString ();
  for (QString &path : o.tableFiles) path = QFileInfo (path).absoluteFilePath ();
  for (QString &path : o.pcfgRulesets)
    if (path.contains ('/') || path.contains ('\\')) path = QFileInfo (path).absoluteFilePath ();
  if (o.feedName.contains ('/') || o.feedName.contains ('\\')) o.feedName = QFileInfo (o.feedName).absoluteFilePath ();
  if (!o.cachePath.isEmpty ()) o.cachePath = QFileInfo (o.cachePath).absoluteFilePath ();
  return o;
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
  if (QSet<int> {0, 1, 3, 4, 5, 6, 7, 8, 9, 12}.contains (attack) == false) return t ("This attack is not supported by the form. Use Commands.", "Режим атаки не поддерживается формой.");
  const HashcatOptions options = command_options ();
  for (const QString &path : options.wordlists)
    if ((readable (path) == false) && (QFileInfo (path).isDir () == false)) return t ("Dictionary is missing: ", "Словарь не найден: ") + path;
  QString detail;
  using Error = HelperUtils::LaunchError;
  const Error option_error = HelperUtils::validateOptions (options, &detail);
  if (option_error != Error::None)
  {
    switch (option_error)
    {
      case Error::NoWordlist: return t ("Select a dictionary.", "Выберите словарь.");
      case Error::WrongWordlistCount: return t ("This mode needs exactly two dictionaries.", "Для этого режима нужны ровно два словаря.");
      case Error::TooManyWordlists: return t ("Too many dictionaries for this mode.", "Для этого режима выбрано слишком много словарей.");
      case Error::WordlistMustBeFile: return t ("The second dictionary must be a file.", "Второй словарь должен быть файлом.");
      case Error::NoMask: return t ("Enter a mask.", "Укажите маску.");
      case Error::NoTable: return t ("Select a substitution table.", "Выберите таблицу замен.");
      case Error::NoFeed: return t ("Enter a feed name or path.", "Укажите имя или путь генератора.");
      case Error::NoHashRecipe: return t ("Hash mode 4000 requires a recipe.", "Для типа хеша 4000 нужен рецепт.");
      case Error::InvalidCachePath: return t ("The cache directory does not exist.", "Каталог кеша не существует.");
      case Error::AssociationSettingsWithWordlist: return t ("Association settings require an empty dictionary list.", "Параметры ассоциации требуют пустого списка словарей.");
      case Error::MaskNeedsWordMarker: return t ("Mode 12 needs one ?w in the mask.", "Режим 12 требует один маркер ?w в маске.");
      case Error::MaskMultipleWordMarkers: return t ("Use only one ?w marker.", "Используйте только один маркер ?w.");
      case Error::MaskMultipleQMarks: return t ("Use only one ?q marker.", "Используйте только один маркер ?q.");
      case Error::MaskQBeforeWord: return t ("Place ?q after ?w.", "Разместите ?q после ?w.");
      case Error::MaskQWithoutWordlist: return t ("?q requires a second dictionary.", "Для ?q нужен второй словарь.");
      case Error::SecondWordlistWithoutQ: return t ("Add ?q for the second dictionary.", "Добавьте ?q для второго словаря.");
      case Error::MaskMarkersNotAllowed: return t ("?w and ?q require mode 12.", "Маркеры ?w и ?q требуют режима 12.");
      case Error::IncrementInMode12: return t ("Mode 12 does not accept increment.", "Режим 12 не поддерживает наращивание длины.");
      case Error::InvalidIncrement: return t ("Check the mask length range.", "Проверьте диапазон длины маски.");
      default: return t ("Invalid attack settings: ", "Недопустимые параметры режима: ") + detail;
    }
  }
  if (attack == 5) for (const QString &path : options.tableFiles)
    if (readable (path) == false) return t ("Table is missing: ", "Таблица не найдена: ") + path;
  if (CommandBuilder::attackUsesMask (options.attackMode))
  {
    if (mask.isEmpty ()) return t ("Enter a mask or a .hcmask file.", "Укажите маску или файл .hcmask.");
    if (mask.startsWith ('-')) return t ("A mask cannot start with a dash. Use a .hcmask file.", "Маска не должна начинаться с дефиса. Используйте файл .hcmask.");
    if (mask.endsWith (".hcmask", Qt::CaseInsensitive) && (readable (mask) == false)) return t ("Mask file not found.", "Файл масок не найден.");
    if (mask.contains ('\n') || mask.contains ('\r') || mask.contains (QChar (0))) return t ("The mask must be a single line.", "Маска должна занимать одну строку.");
    if (QFileInfo (mask).isFile () == false)
    {
      if (QFileInfo (QDir (QFileInfo (binary).absolutePath ()).filePath (mask)).isFile ())
        return t ("This mask matches a file in the engine directory. Put the literal mask in a .hcmask file, or select the intended file by its full path.", "Маска совпадает с файлом в каталоге движка. Сохраните текст маски в .hcmask либо укажите полный путь к нужному файлу.");
      for (qsizetype i = 0; i < mask.size (); ++i)
      {
        if (mask[i] != '?') continue;
        ++i;
        if ((i == mask.size ()) || ((QString ("ludhHsab1234?") + (attack == 12 ? "wq" : "")).contains (mask[i]) == false)) return t ("Invalid mask token after ?.", "Неверный символ маски после ?.");
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
  if (CommandBuilder::attackUsesRules (options.attackMode)) for (const QString &rule : rules)
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
  QStringList args {"--session=" + id, "--status", "--status-json", "--status-timer=1",
    "--restore-file-path=" + dir + "/session.restore",
    "--outfile=" + dir + "/results.txt", "--outfile-format=1,3", "--logfile-disable",
    "-w", QString::number (workload)};
  if (restore) args << "--restore-position";
  if (attack != 9) args << "--potfile-path=" + dir + "/hashcat.potfile";
  args << extra << CommandBuilder::build (command_options ());
  return args;
}

QJsonObject Job::json () const
{
  QJsonObject obj;
  obj["id"] = id; obj["name"] = name; obj["binary"] = binary; obj["hashes"] = hashes;
  obj["dictionary"] = dictionary; obj["dictionary2"] = dictionary2; obj["mask"] = mask; obj["devices"] = devices;
  obj["rules"] = QJsonArray::fromStringList (rules); obj["extra"] = QJsonArray::fromStringList (extra);
  obj["wordlists"] = QJsonArray::fromStringList (wordlists); obj["advanced"] = advanced; obj["editor_state"] = editor_state;
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
  for (const auto &path : obj["wordlists"].toArray ()) job.wordlists << path.toString ();
  job.advanced = obj["advanced"].toObject ();
  job.editor_state = obj["editor_state"].toObject ();
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
