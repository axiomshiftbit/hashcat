/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "window.h"
#include "lang.h"
#include "pathlist.h"
#include "advancedform.h"
#include "telemetry.h"
#include "bundled_tools.h"

#include <QtTest>
#include <QCheckBox>
#include <QComboBox>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QJsonDocument>
#include <QJsonArray>
#include <QCryptographicHash>

class DesktopTest : public QObject
{
  Q_OBJECT
  QTemporaryDir temp;
  QString fake;

  QString file (const QString &name, const QByteArray &data = "test\n")
  {
    const QString path = temp.filePath (name);
    QFile f (path);
    if (f.open (QIODevice::WriteOnly)) f.write (data);
    return path;
  }

  Job job ()
  {
    Job j; j.id = QUuid::createUuid ().toString (QUuid::Id128); j.name = "Test"; j.binary = fake;
    j.hashes = file ("synthetic hashes.txt", "098f6bcd4621d373cade4e832627b4f6\n");
    j.dictionary = file ("dictionary with spaces.txt");
    return j;
  }

private slots:
  void initTestCase ()
  {
    QVERIFY (temp.isValid ());
    qApp->setProperty ("language", "en");
    fake = QDir (QCoreApplication::applicationDirPath ()).filePath (
#ifdef Q_OS_WIN
      "fake_hashcat.exe"
#else
      "fake_hashcat"
#endif
    );
    QVERIFY (QFileInfo (fake).isExecutable ());
  }

  void arguments_data ()
  {
    QTest::addColumn<int> ("attack");
    for (int mode : {0, 1, 3, 6, 7, 9}) QTest::newRow (qPrintable (QString::number (mode))) << mode;
  }

  void arguments ()
  {
    QFETCH (int, attack);
    Job j = job (); j.attack = attack; j.mask = "?l?l?d"; j.dictionary2 = file ("second.txt");
    QVERIFY2 (j.validate ().isEmpty (), qPrintable (j.validate ()));
    const auto args = j.arguments (temp.path ());
    QVERIFY (args.contains ("--outfile-format=1,3"));
    QVERIFY (args.contains (j.hashes));
    QCOMPARE (args[args.indexOf ("-a") + 1].toInt (), attack);
    if (attack == 3) QCOMPARE (args.last (), j.mask);
    if (attack == 6) QCOMPARE (args.mid (args.size () - 2), QStringList ({j.dictionary, j.mask}));
    if (attack == 7) QCOMPARE (args.mid (args.size () - 2), QStringList ({j.mask, j.dictionary}));
    if (attack == 1) QCOMPARE (args.mid (args.size () - 2), QStringList ({j.dictionary, j.dictionary2}));
  }

  void validation ()
  {
    Job j = job (); QVERIFY (j.validate ().isEmpty ());
    j.id = "../escape"; QVERIFY (j.validate ().isEmpty () == false); j.id = "valid";
    j.hashes += ".missing"; QVERIFY (j.validate ().isEmpty () == false); j = job ();
    j.devices = "1;2"; QVERIFY (j.validate ().isEmpty () == false); j.devices = "1,2";
    j.attack = 3; j.mask = "?1?d"; QVERIFY (j.validate ().isEmpty () == false);
    j.charsets[0] = "abc"; QVERIFY (j.validate ().isEmpty ());
    j.mask = "?x"; QVERIFY (j.validate ().isEmpty () == false);
    j.mask = "abc?"; QVERIFY (j.validate ().isEmpty () == false);
    j.mask = QFileInfo (fake).fileName ();
    const QString cwd = QDir::currentPath (); QVERIFY (QDir::setCurrent (temp.path ()));
    const QString collision = j.validate ();
    QVERIFY (QDir::setCurrent (cwd)); QVERIFY (collision.isEmpty () == false);
    j.mask = "?d?d"; j.increment = true; j.minimum = 8; j.maximum = 2; QVERIFY (j.validate ().isEmpty () == false);
    j = job (); j.extra = {"--outfile=/tmp/escape"}; QVERIFY (j.validate ().isEmpty () == false);
    j.extra = {"--encoding-from=UTF-8"}; QVERIFY (j.validate ().isEmpty ());
    QTemporaryDir dictionaries; j = job (); j.dictionary = dictionaries.path ();
    QVERIFY (!j.validate ().isEmpty ());
    QFile hidden (dictionaries.filePath (".hidden")); QVERIFY (hidden.open (QIODevice::WriteOnly)); hidden.write ("fixture\n"); hidden.close ();
    QVERIFY (!j.validate ().isEmpty ());
    QVERIFY (hidden.rename (dictionaries.filePath ("visible.txt")));
    QVERIFY (j.validate ().isEmpty ());
  }

  void profiles_and_restore_arguments ()
  {
    Job j = job (); j.rules = {file ("rule file.rule", ":\n")}; j.charsets[0] = "?l?d";
    j.username = true; j.runtime = 15; j.workload = 3; j.device_type = 1;
    QCOMPARE (Job::from_json (j.json ()).json (), j.json ());
    const auto modern = j.arguments (temp.path (), true, true);
    QVERIFY (modern.contains ("--restore-position")); QVERIFY (modern.contains (j.hashes));
    const auto legacy = j.arguments (temp.path (), true, false);
    QVERIFY (legacy.contains ("--restore")); QVERIFY (legacy.contains (j.hashes) == false);
    QString error; QVERIFY (save_json (temp.filePath ("profile.json"), j.json (), &error));
  }

  void parser_and_languages ()
  {
    QCOMPARE (parse_modes ("0 | MD5 | Raw\n22000 | WPA | Network\ninvalid").size (), 2);
    qApp->setProperty ("language", "en"); QCOMPARE (state_text ("running"), QString ("Running"));
    qApp->setProperty ("language", "ru"); QCOMPARE (state_text ("running"), QString::fromUtf8 ("Выполняется"));
    qApp->setProperty ("language", "en");
    QCOMPARE (speed_text (1200), QString ("1.20 kH/s"));
  }

  void process_partial_output_and_exit ()
  {
    Runner runner; QSignalSpy statuses (&runner, &Runner::status); QSignalSpy logs (&runner, &Runner::line); QSignalSpy done (&runner, &Runner::finished);
    QVERIFY (runner.start (fake, {}, temp.path ()));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000);
    QCOMPARE (done[0][0].toInt (), 0); QVERIFY (statuses.size () >= 3);
    QCOMPARE (statuses[0][0].toJsonObject ()["devices"].toArray ().size (), 1);
    bool tail = false; for (const auto &entry : logs) if (entry[0].toString ().contains ("without trailing newline")) tail = true;
    QVERIFY (tail); QVERIFY (runner.busy () == false);
  }

  void terminal_controls ()
  {
    Runner runner; QSignalSpy statuses (&runner, &Runner::status); QSignalSpy logs (&runner, &Runner::line); QSignalSpy done (&runner, &Runner::finished);
    QVERIFY (runner.start (fake, {"--fixture-wait"}, temp.path ()));
    QTRY_VERIFY_WITH_TIMEOUT (statuses.size () > 0, 10000);
    bool terminal = false;
    for (const auto &entry : logs) if (entry[0].toString () == "TERMINAL_READY") terminal = true;
    QVERIFY (terminal);
    QVERIFY (runner.command ('p'));
    QTRY_COMPARE_WITH_TIMEOUT (statuses.last ()[0].toJsonObject ()["status"].toInt (), 4, 10000);
    QVERIFY (runner.command ('r'));
    QTRY_COMPARE_WITH_TIMEOUT (statuses.last ()[0].toJsonObject ()["status"].toInt (), 3, 10000);
    QVERIFY (runner.command ('c'));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000); QCOMPARE (done[0][0].toInt (), 3);
  }

  void arguments_are_not_shell_code ()
  {
    Runner runner; QSignalSpy logs (&runner, &Runner::line); QSignalSpy done (&runner, &Runner::finished);
    const QString value = "space ; $(not-executed) & \"quoted\" \\ Юникод";
    QVERIFY (runner.start (fake, {"--fixture-arguments", value}, temp.path (), false));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000);
    QJsonArray array;
    for (const auto &entry : logs)
    {
      const auto doc = QJsonDocument::fromJson (entry[0].toString ().toUtf8 ());
      if (doc.isArray ()) array = doc.array ();
    }
    QCOMPARE (array[1].toString (), value);
  }

  void failure_and_double_start ()
  {
    Runner runner; QSignalSpy done (&runner, &Runner::finished);
    QVERIFY (runner.start (fake, {"--fixture-failure"}, temp.path ()));
    QVERIFY (runner.start (fake, {}, temp.path ()) == false);
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000); QCOMPARE (done[0][0].toInt (), 255);
    done.clear ();
    QVERIFY (runner.start (temp.filePath ("missing-binary"), {}, temp.path ()));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000); QVERIFY (done[0][1].toBool ());
  }

  void cancellation_stops_descendants ()
  {
    const QString marker = file ("child heartbeat.txt", "");
    Runner runner; QSignalSpy done (&runner, &Runner::finished);
    QVERIFY (runner.start (fake, {"--fixture-parent", marker}, temp.path (), false));
    QTRY_VERIFY (QFileInfo (marker).size () > 0);
    runner.kill (); QTRY_COMPARE (done.size (), 1);
    QTest::qWait (150);
    const qint64 stopped_size = QFileInfo (marker).size ();
    QTest::qWait (350); QCOMPARE (QFileInfo (marker).size (), stopped_size);
    Extractor extractor; QSignalSpy extracted (&extractor, &Extractor::finished);
    Extraction request; request.tool = fake; request.hashcat = fake; request.input = marker;
    request.output = temp.filePath ("cancelled-child.hashes"); request.arguments = {"--fixture-parent"};
    QVERIFY (extractor.start (request));
    QTRY_VERIFY (QFileInfo (marker).size () > stopped_size);
    extractor.cancel (); QTRY_COMPARE (extracted.size (), 1);
    QTest::qWait (150);
    const qint64 canceled_size = QFileInfo (marker).size ();
    QTest::qWait (350); QCOMPARE (QFileInfo (marker).size (), canceled_size);
    QVERIFY (!QFileInfo::exists (request.output));
  }

  void ui_queue_language_results_and_reload ()
  {
    QTemporaryDir workspace;
    Window window (workspace.path ()); window.show ();
    Job j = job (); window.set_form (j);
    auto *lang = window.findChild<QComboBox *> ("language");
    lang->setCurrentIndex (1);
    QCOMPARE (window.findChild<QPushButton *> ("addJob")->text (), QString ("Add to queue"));
    lang->setCurrentIndex (0);
    QCOMPARE (window.findChild<QPushButton *> ("addJob")->text (), QString::fromUtf8 ("В очередь"));
    auto *nav = window.findChild<QListWidget *> ("navigation");
    nav->setCurrentRow (1);
    QTest::mouseClick (window.findChild<QPushButton *> ("addJob"), Qt::LeftButton);
    auto *table = window.findChild<QTableWidget *> ("jobs"); QCOMPARE (table->rowCount (), 1);
    window.findChild<QCheckBox *> ("autoNext")->setChecked (true);
    nav->setCurrentRow (1);
    QTest::mouseClick (window.findChild<QPushButton *> ("addJob"), Qt::LeftButton);
    QCOMPARE (table->rowCount (), 2);
    table->selectRow (0);
    QTest::mouseClick (window.findChild<QPushButton *> ("runSelected"), Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT (table->item (1, 3)->text (), state_text ("completed"), 15000);
    QCOMPARE (window.findChild<QTableWidget *> ("results")->rowCount (), 1);
    QCOMPARE (window.findChild<QTableWidget *> ("results")->item (0, 1)->text (), QString ("sample"));
    const QString screenshot = qEnvironmentVariable ("GUI_SCREENSHOT");
    if (screenshot.isEmpty () == false)
    {
      QVERIFY (window.grab ().save (screenshot));
      for (int language = 0; language < 2; ++language)
      {
        lang->setCurrentIndex (language);
        for (int page = 0; page < nav->count (); ++page)
        {
          nav->setCurrentRow (page); QCoreApplication::processEvents ();
          QVERIFY (window.grab ().save (screenshot + QString ("-%1-%2.png").arg (language).arg (page)));
        }
      }
    }
    window.close ();
    Window reopened (workspace.path ());
    QCOMPARE (reopened.findChild<QTableWidget *> ("jobs")->rowCount (), 2);
    QVERIFY (reopened.engine ()->busy () == false);
  }

  void ui_expert_any_arguments ()
  {
    QTemporaryDir workspace; Window window (workspace.path ()); window.show ();
    window.set_form (job ()); window.findChild<QListWidget *> ("navigation")->setCurrentRow (2);
    window.findChild<QPlainTextEdit *> ("arguments")->setPlainText ("[\"--fixture-arguments\",\"--future-option=anything\",\"space path\"]");
    QTest::mouseClick (window.findChild<QPushButton *> ("expertRun"), Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT (window.findChild<QPlainTextEdit *> ("consoleOutput")->toPlainText ().contains ("--future-option=anything"), 10000);
    QTRY_VERIFY (window.engine ()->busy () == false);
    const QByteArray input = "synthetic standard input with spaces\nsecond line\n";
    window.findChild<QLineEdit *> ("stdinFile")->setText (file ("input with spaces.txt", input));
    window.findChild<QPlainTextEdit *> ("arguments")->setPlainText ("--fixture-stdin");
    QTest::mouseClick (window.findChild<QPushButton *> ("expertRun"), Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT (window.findChild<QPlainTextEdit *> ("consoleOutput")->toPlainText ().contains (QString::fromLatin1 (input.toBase64 ())), 10000);
    QTRY_VERIFY (window.engine ()->busy () == false);
  }

  void damaged_workspace_is_preserved ()
  {
    const QList<QByteArray> inputs {"{broken", "[]", "{\"version\":2,\"jobs\":[]}",
      "{\"version\":1,\"jobs\":[{\"id\":\"../escape\"}]}",
      "{\"version\":1,\"jobs\":[{\"id\":\"same\"},{\"id\":\"same\"}]}"};
    for (const auto &bytes : inputs)
    {
      QTemporaryDir workspace;
      QFile state (workspace.filePath ("workspace.json"));
      QVERIFY (state.open (QIODevice::WriteOnly)); QCOMPARE (state.write (bytes), bytes.size ()); state.close ();
      Window window (workspace.path ()); window.show ();
      window.findChild<QComboBox *> ("language")->setCurrentIndex (1);
      window.close ();
      QVERIFY (state.open (QIODevice::ReadOnly)); QCOMPARE (state.readAll (), bytes);
    }
  }

  void ui_converter_to_task ()
  {
    const QString fixtures = qEnvironmentVariable ("CAPTURE_FIXTURES");
    if (fixtures.isEmpty ()) QSKIP ("CAPTURE_FIXTURES not supplied");
    QTemporaryDir workspace; Window window (workspace.path ()); window.show ();
    auto *nav = window.findChild<QListWidget *> ("navigation"); nav->setCurrentRow (3);
    const QString output = workspace.filePath ("converted hashes.txt");
    window.findChild<QLineEdit *> ("conversionInput")->setText (QDir (fixtures).filePath ("synthetic.pcapng"));
    window.findChild<QLineEdit *> ("conversionOutput")->setText (output);
    if (!qEnvironmentVariableIsSet ("BUNDLED_TOOL_TEST"))
    {
      window.findChild<QLineEdit *> ("hcxDirectory")->setText (qEnvironmentVariable ("HCX_DIRECTORY"));
      window.findChild<QCheckBox *> ("useWsl")->setChecked (qEnvironmentVariableIsSet ("HCX_WSL"));
    }
    else
    {
      QCOMPARE (window.findChild<QLineEdit *> ("hcxDirectory")->text (), bundled_tool ("hcxtools"));
      QVERIFY (!window.findChild<QCheckBox *> ("useWsl")->isChecked ());
    }
    QTest::mouseClick (window.findChild<QPushButton *> ("convert"), Qt::LeftButton);
    // Changing the form must not alter the mode of the in-flight conversion.
    window.findChild<QComboBox *> ("conversionMode")->setCurrentIndex (1);
    auto *use = window.findChild<QPushButton *> ("useConversion");
    QTRY_VERIFY2_WITH_TIMEOUT (use->isEnabled (), qPrintable (window.findChild<QPlainTextEdit *> ("conversionLog")->toPlainText ()), 30000);
    QTest::mouseClick (use, Qt::LeftButton);
    QCOMPARE (nav->currentRow (), 1);
    QCOMPARE (window.form_job ().hashes, output);
    QCOMPARE (window.form_job ().hash_mode, 22000);
    QVERIFY (QFileInfo (output).size () > 0);
  }

  void real_hashcat_dictionary_data ()
  {
    QTest::addColumn<int> ("attack");
    QTest::addColumn<bool> ("mask_file");
    for (int mode : {0, 1, 3, 4, 5, 6, 7, 8, 9, 12}) QTest::newRow (qPrintable (QString::number (mode))) << mode << false;
    QTest::newRow ("mask-file") << 3 << true;
  }

  void merged_forms_and_profile ()
  {
    QTemporaryDir workspace; Window window (workspace.path ());
    QCOMPARE (window.findChild<QComboBox *> ("attack")->count (), 10);
    Job legacy = job (); legacy.dictionary2 = file ("unused legacy dictionary.txt");
    window.set_form (legacy); QCOMPARE (window.form_job ().wordlists, QStringList {QDir::toNativeSeparators (legacy.dictionary)});
    Job j = job (); j.attack = 12; j.mask = "?w?q";
    j.wordlists = {file ("first selected.txt", "te\n"), file ("second selected.txt", "st\n")};
    j.advanced = {{"ruleLeft", ":"}, {"skip", "10"}, {"pcfgScale", "4"}};
    window.set_form (j);
    auto *paths = window.findChild<PathList *> ("wordlists");
    auto *list = paths->findChild<QListWidget *> ("entries");
    paths->add_paths ({file ("disabled.txt"), j.wordlists[0]});
    QCOMPARE (list->count (), 3);
    list->item (2)->setCheckState (Qt::Unchecked);
    list->setCurrentRow (1); paths->move_selected (-1);
    const Job captured = window.form_job ();
    QCOMPARE (captured.wordlists, QStringList ({QDir::toNativeSeparators (j.wordlists[1]), QDir::toNativeSeparators (j.wordlists[0])}));
    const Job restored = Job::from_json (captured.json ()); window.set_form (restored);
    QCOMPARE (paths->snapshot (), captured.editor_state["wordlists"].toArray ());
    QCOMPARE (window.form_job ().advanced["pcfgScale"].toString (), QString ("4"));
    QVERIFY (!window.form_job ().arguments (workspace.path ()).contains ("scale=4"));
    QVERIFY (window.form_job ().arguments (workspace.path ()).contains ("?w?q"));
    list->item (0)->setCheckState (Qt::Unchecked); list->item (1)->setCheckState (Qt::Unchecked);
    QVERIFY (!window.form_job ().validate ().isEmpty ());
    auto *advanced = window.findChild<AdvancedForm *> ("advanced");
    window.findChild<QComboBox *> ("attack")->setCurrentIndex (window.findChild<QComboBox *> ("attack")->findData (4));
    QVERIFY (advanced->isTabEnabled (1)); QVERIFY (!advanced->isTabEnabled (2));
    QCOMPARE (window.findChild<QComboBox *> ("extractKind")->count (), 78);
    auto *telemetry = window.findChild<Telemetry *> ("telemetry");
    for (int i = 0; i < 70; ++i) window.engine ()->status ({{"devices", QJsonArray {QJsonObject {{"speed", i * 100.0}, {"device_id", 1}}}}});
    QCOMPARE (telemetry->sample_count (), 60); telemetry->clear (); QCOMPARE (telemetry->sample_count (), 0);
  }

  void extractor_process_and_validation ()
  {
    Extractor extractor; QSignalSpy done (&extractor, &Extractor::finished);
    Extraction request; request.input = file ("synthetic input.pdf"); request.output = temp.filePath ("new extracted.hash");
    request.tool = fake; request.hashcat = fake; request.arguments = {"--fixture-extract"};
    QVERIFY (extractor.start (request)); QVERIFY (!extractor.start (request));
    QTRY_COMPARE (done.size (), 1); QVERIFY (done[0][0].toBool ());
    QCOMPARE (qvariant_cast<QList<int>> (done[0][2]), QList<int> ({10500, 10600}));
    QFile hash (request.output); QVERIFY (hash.open (QIODevice::ReadOnly)); QCOMPARE (hash.readAll (), QByteArray ("$pdf$fixture\n")); hash.close ();
    QVERIFY (!extractor.start (request));
    request.output = temp.filePath ("concurrent-output.hash"); request.arguments = {"--fixture-delayed-extract"}; done.clear ();
    QVERIFY (extractor.start (request));
    file ("concurrent-output.hash", "created while extracting");
    QTRY_COMPARE (done.size (), 1); QVERIFY (!done[0][0].toBool ());
    QFile concurrent (request.output); QVERIFY (concurrent.open (QIODevice::ReadOnly));
    QCOMPARE (concurrent.readAll (), QByteArray ("created while extracting"));
    request.output = temp.filePath ("incompatible.hash"); request.arguments = {"--fixture-incompatible"}; done.clear ();
    QVERIFY (extractor.start (request)); QTRY_COMPARE (done.size (), 1); QVERIFY (!done[0][0].toBool ()); QVERIFY (!QFileInfo::exists (request.output));
    request.arguments = {"--fixture-empty"}; done.clear ();
    QVERIFY (extractor.start (request)); QTRY_COMPARE (done.size (), 1); QVERIFY (!done[0][0].toBool ());
    request.arguments = {"--fixture-wait"}; done.clear ();
    QVERIFY (extractor.start (request)); extractor.cancel (); QTRY_COMPARE (done.size (), 1); QVERIFY (!done[0][0].toBool ());
    QCOMPARE (Extractor::normalize ("C:/price $5.rar:$RAR3$*0*abc::::metadata\nC:/price $5.rar:$RAR3$*0*abc::::metadata\n"), QByteArray ("$RAR3$*0*abc\n"));
    QCOMPARE (Extractor::normalize ("$pdf$2*3*128*4294967292*1*32*abc\n"), QByteArray ("$pdf$2*3*128*-4*1*32*abc\n"));
    QCOMPARE (Extractor::normalize ("$pdf$2*3*128*-4*1*32*abc\n"), QByteArray ("$pdf$2*3*128*-4*1*32*abc\n"));
    QCOMPARE (Extractor::normalize ("$pdf$2*3*128*2147483648*1*32*abc\n"), QByteArray ("$pdf$2*3*128*-2147483648*1*32*abc\n"));
    QCOMPARE (Extractor::normalize ("$pdf$2*3*128*2147483647*1*32*abc\n"), QByteArray ("$pdf$2*3*128*2147483647*1*32*abc\n"));
    QCOMPARE (Extractor::normalize ("$pdf$2*3*128*4294967296*1*32*abc\n"), QByteArray ("$pdf$2*3*128*4294967296*1*32*abc\n"));
  }

  void real_document_extraction_data ()
  {
    QTest::addColumn<QString> ("format");
    QTest::newRow ("PDF") << "pdf"; QTest::newRow ("Office") << "docx"; QTest::newRow ("7z") << "7z";
    if (qEnvironmentVariableIsSet ("BUNDLED_TOOL_TEST")) QTest::newRow ("ZIP native") << "zip";
  }

  void real_document_extraction ()
  {
    QFETCH (QString, format);
    const QString fixtures = qEnvironmentVariable ("DOCUMENT_FIXTURES"), john = qEnvironmentVariable ("JOHN_RUN");
    const QString binary = qEnvironmentVariable ("REAL_HASHCAT"), python = qEnvironmentVariable ("TEST_PYTHON");
    const bool bundled = qEnvironmentVariableIsSet ("BUNDLED_TOOL_TEST");
    if (fixtures.isEmpty () || binary.isEmpty () || (!bundled && (john.isEmpty () || python.isEmpty ()))) QSKIP ("Document integration dependencies not supplied");
    const QString perl = qEnvironmentVariable ("TEST_PERL");
    if (!bundled && format == "7z" && perl.isEmpty ()) QSKIP ("7z integration requires Perl with Compress::Raw::Lzma");
    QTemporaryDir workspace; Window window (workspace.path ()); window.show ();
    window.findChild<QLineEdit *> ("binary")->setText (binary);
    auto *kind = window.findChild<QComboBox *> ("extractKind");
    kind->setCurrentIndex (kind->findData (format == "docx" ? "office" : format));
    if (!bundled)
    {
      window.findChild<QLineEdit *> ("johnDirectory")->setText (john);
      window.findChild<QLineEdit *> ("extractTool")->setText (QDir (john).filePath (format == "pdf" ? "pdf2john.py" : format == "7z" ? "7z2john.pl" : "office2john.py"));
      window.findChild<QLineEdit *> ("extractInterpreter")->setText (format == "7z" ? perl : python);
    }
    else
    {
      QCOMPARE (window.findChild<QLineEdit *> ("johnDirectory")->text (), bundled_tool ("john/run"));
      QVERIFY (window.findChild<QLineEdit *> ("extractInterpreter")->text ().isEmpty ());
      QVERIFY (QFileInfo (window.findChild<QLineEdit *> ("extractTool")->text ()).isFile ());
    }
    window.findChild<QLineEdit *> ("extractInput")->setText (QDir (fixtures).filePath ("synthetic." + format));
    const QString hashfile = workspace.filePath ("extracted.hashes");
    window.findChild<QLineEdit *> ("extractOutput")->setText (hashfile);
    window.findChild<QPushButton *> ("extractStart")->click ();
    QTRY_VERIFY_WITH_TIMEOUT (window.findChild<QPushButton *> ("extractStart")->isEnabled (), 180000);
    QVERIFY2 (window.findChild<QPushButton *> ("extractUse")->isEnabled (), qPrintable (window.findChild<QPlainTextEdit *> ("extractLog")->toPlainText ()));
    auto *modes = window.findChild<QComboBox *> ("extractModes");
    const int mode = format == "pdf" ? 10500 : format == "7z" ? 11600 : format == "zip" ? 13600 : 9600;
    QVERIFY (modes->findData (mode) >= 0); modes->setCurrentIndex (modes->findData (mode));
    window.findChild<QPushButton *> ("extractUse")->click ();
    QCOMPARE (window.form_job ().hashes, hashfile); QCOMPARE (window.form_job ().hash_mode, mode);
    Job j = job (); j.binary = binary; j.hashes = hashfile; j.hash_mode = mode;
    j.dictionary = QDir (fixtures).filePath ("dictionary.txt"); j.device_type = 1; j.workload = 1; j.force = true;
    QVERIFY (QDir ().mkpath (j.directory (workspace.path ())));
    Runner runner; QSignalSpy done (&runner, &Runner::finished);
    QStringList log;
    connect (&runner, &Runner::line, &runner, [&log] (const QString &line) { log << line; });
    QStringList args = j.arguments (workspace.path ());
    QVERIFY (runner.start (binary, args, QFileInfo (binary).absolutePath ()));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 120000);
    QVERIFY2 (done[0][0].toInt () == 0, qPrintable (QString ("Hashcat exit code: %1\n%2").arg (done[0][0].toInt ()).arg (log.join ('\n'))));
    QFile result (j.directory (workspace.path ()) + "/results.txt"); QVERIFY (result.open (QIODevice::ReadOnly));
    QVERIFY (result.readAll ().contains (QByteArray ("gui-fixture-only").toHex ()));
    const QString screenshot = qEnvironmentVariable ("GUI_SCREENSHOT");
    if (!screenshot.isEmpty ())
    {
      window.findChild<QListWidget *> ("navigation")->setCurrentRow (3);
      window.findChild<QTabWidget *> ("converterTabs")->setCurrentIndex (1); QCoreApplication::processEvents ();
      QVERIFY (window.grab ().save (screenshot + "-extract-" + format + ".png"));
    }
    const QString invalid_output = workspace.filePath ("invalid-document.hashes");
    window.findChild<QLineEdit *> ("extractInput")->setText (file ("invalid." + format, "not an encrypted document"));
    window.findChild<QLineEdit *> ("extractOutput")->setText (invalid_output);
    window.findChild<QPushButton *> ("extractStart")->click ();
    QTRY_VERIFY_WITH_TIMEOUT (window.findChild<QPushButton *> ("extractStart")->isEnabled (), 30000);
    QVERIFY (!window.findChild<QPushButton *> ("extractUse")->isEnabled ());
    QVERIFY (!QFileInfo::exists (invalid_output));
  }

  void real_hashcat_dictionary ()
  {
    QFETCH (int, attack);
    QFETCH (bool, mask_file);
    const QString binary = qEnvironmentVariable ("REAL_HASHCAT");
    if (binary.isEmpty ()) QSKIP ("REAL_HASHCAT not supplied");
    Job j = job (); j.binary = binary; j.device_type = 1; j.workload = 1; j.force = true;
    j.attack = attack;
    if (attack == 1) { j.dictionary = file ("left.dict", "te\n"); j.dictionary2 = file ("right.dict", "st\n"); }
    if (attack == 3) j.mask = mask_file ? file ("literal.hcmask", "test\n") : QString ("tes?l");
    if (attack == 6) { j.dictionary = file ("left.dict", "te\n"); j.mask = "st"; }
    if (attack == 7) { j.dictionary = file ("right.dict", "st\n"); j.mask = "te"; }
    if (attack == 4 || attack == 5 || attack == 8 || attack == 12)
    {
      QProcess version; version.start (binary, {"--version"}); QVERIFY (version.waitForFinished (10000));
      if (!version.readAllStandardOutput ().trimmed ().startsWith ("v8.")) QSKIP ("New feed modes require Hashcat 8");
    }
    if (attack == 4)
    {
      j.advanced["pcfgRulesets"] = QJsonArray {"hints"};
      j.advanced["pcfgExtraSettings"] = QJsonArray {"hintwords=test"};
      j.advanced["pcfgMask"] = "test"; j.advanced["pcfgThreads"] = "1"; j.advanced["pcfgKbits"] = "16";
    }
    if (attack == 5)
    {
      j.dictionary = file ("table words.txt", "t3st\n");
      j.advanced["tableFiles"] = QJsonArray {file ("substitutions.table", "3\te\n")};
    }
    if (attack == 8) { j.advanced["feedName"] = "wordlist"; j.advanced["feedArguments"] = QJsonArray {j.dictionary}; }
    if (attack == 12) { j.dictionary = file ("hybrid left.txt", "te\n"); j.dictionary2 = file ("hybrid right.txt", "st\n"); j.mask = "?w?q"; }
    QVERIFY2 (j.validate ().isEmpty (), qPrintable (j.validate ()));
    const QString directory = j.directory (temp.path ()); QVERIFY (QDir ().mkpath (directory));
    Runner runner; QSignalSpy done (&runner, &Runner::finished);
    QStringList log;
    connect (&runner, &Runner::line, &runner, [&log] (const QString &text) { log << text; });
    QVERIFY (runner.start (binary, j.arguments (temp.path ()), QFileInfo (binary).absolutePath ()));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 120000);
    if (done[0][0].toInt () != 0) for (const QString &line : log) qWarning ().noquote () << line;
    QCOMPARE (done[0][0].toInt (), 0);
    QFile results (directory + "/results.txt"); QVERIFY (results.open (QIODevice::ReadOnly));
    QVERIFY (results.readAll ().contains (":74657374"));
  }

  void real_controls_and_restore ()
  {
    const QString binary = qEnvironmentVariable ("REAL_HASHCAT");
    if (binary.isEmpty ()) QSKIP ("REAL_HASHCAT not supplied");
    QTemporaryDir workspace;
    Window window (workspace.path ()); window.show ();
    Job j = job (); j.binary = binary; j.device_type = 1; j.workload = 1; j.force = true;
    j.attack = 3; j.mask = "?d?d?d?d?d?d?d?d?d?d?d?d";
    window.set_form (j);
    window.findChild<QListWidget *> ("navigation")->setCurrentRow (1);
    QTest::mouseClick (window.findChild<QPushButton *> ("addJob"), Qt::LeftButton);
    QSignalSpy done (window.engine (), &Runner::finished);
    auto *pause = window.findChild<QPushButton *> ("pause");
    auto *resume = window.findChild<QPushButton *> ("resume");
    QTest::mouseClick (window.findChild<QPushButton *> ("runSelected"), Qt::LeftButton);
    QTRY_VERIFY2_WITH_TIMEOUT (pause->isEnabled (), qPrintable (window.findChild<QPlainTextEdit *> ("log")->toPlainText ()), 120000);
    QVERIFY (resume->isEnabled () == false);
    QTest::mouseClick (pause, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT (resume->isEnabled (), 10000);
    QVERIFY (pause->isEnabled () == false);
    QTest::mouseClick (resume, Qt::LeftButton);
    QTRY_VERIFY_WITH_TIMEOUT (pause->isEnabled (), 10000);
    QTest::mouseClick (window.findChild<QPushButton *> ("checkpoint"), Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 90000);
    QCOMPARE (done[0][0].toInt (), 3);
    auto *restore = window.findChild<QPushButton *> ("restore");
    QVERIFY (restore->isEnabled ());
    done.clear ();
    QTest::mouseClick (restore, Qt::LeftButton);
    QTRY_VERIFY2_WITH_TIMEOUT (pause->isEnabled (), qPrintable (window.findChild<QPlainTextEdit *> ("log")->toPlainText ()), 120000);
    QTest::mouseClick (window.findChild<QPushButton *> ("stop"), Qt::LeftButton);
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 15000);
    QCOMPARE (done[0][0].toInt (), 2);
    QVERIFY (done[0][1].toBool () == false);
    window.close ();
  }

  void converter_missing_tool_and_existing_output ()
  {
    Converter converter; QSignalSpy done (&converter, &Converter::finished);
    Conversion request; request.input = file ("invalid.pcap", "not a capture"); request.output = file ("existing.hashes", "preserve");
    QVERIFY (converter.start (request) == false);
    QFile existing (request.output); QVERIFY (existing.open (QIODevice::ReadOnly)); QCOMPARE (existing.readAll (), QByteArray ("preserve"));
    request.output = temp.filePath ("new.hashes"); request.tools_directory = temp.filePath ("no-tools");
    QVERIFY (converter.start (request));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 10000); QVERIFY (done[0][0].toBool () == false);
    QVERIFY (QFileInfo::exists (request.output) == false);
  }

  void real_converter_data ()
  {
    QTest::addColumn<QString> ("input"); QTest::addColumn<int> ("mode");
    for (const char *suffix : {"cap", "pcap", "pcapng", "pcap.gz", "16800", "hccapx", "hccap"})
      QTest::newRow (suffix) << "synthetic." + QString::fromLatin1 (suffix) << 22000;
    QTest::newRow ("EAP-MD5") << QString ("eap-md5.pcap") << 4800;
    QTest::newRow ("LEAP") << QString ("eap-leap.pcap") << 5500;
    QTest::newRow ("TACACS+") << QString ("tacacs.pcap") << 16100;
  }

  void real_converter ()
  {
    QFETCH (QString, input); QFETCH (int, mode);
    const QString fixtures = qEnvironmentVariable ("CAPTURE_FIXTURES");
    if (fixtures.isEmpty ()) QSKIP ("CAPTURE_FIXTURES not supplied");
    Converter converter; QSignalSpy done (&converter, &Converter::finished);
    QStringList log; connect (&converter, &Converter::log, &converter, [&log] (const QString &text) { log << text; });
    Conversion request; request.input = QDir (fixtures).filePath (input); request.mode = mode;
    request.output = temp.filePath (input + ".converted"); request.tools_directory = qEnvironmentVariable ("HCX_DIRECTORY");
    request.wsl = qEnvironmentVariableIsSet ("HCX_WSL");
    QVERIFY (converter.start (request));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 20000);
    QVERIFY2 (done[0][0].toBool (), qPrintable (log.join ('\n')));
    QVERIFY (done[0][2].toInt () > 0);
    QFile result (request.output); QVERIFY (result.open (QIODevice::ReadOnly));
    const QByteArray data = result.readAll ();
    if (mode == 22000) QVERIFY (data.startsWith ("WPA*"));
    if (QStringList {"synthetic.cap", "synthetic.pcap", "synthetic.pcapng", "synthetic.pcap.gz", "synthetic.16800"}.contains (input))
    {
      if (mode == 22000)
      {
        QFile expected (QDir (fixtures).filePath ("expected-pmkid.txt")); QVERIFY (expected.open (QIODevice::ReadOnly));
        QCOMPARE (data.split ('*').mid (0, 6), expected.readAll ().split ('*').mid (0, 6));
      }
    }
    const QString binary = qEnvironmentVariable ("REAL_HASHCAT");
    if ((binary.isEmpty () == false) && QStringList {"synthetic.cap", "synthetic.hccapx", "eap-md5.pcap", "tacacs.pcap"}.contains (input))
    {
      Job j = job (); j.binary = binary; j.hashes = request.output; j.hash_mode = mode;
      j.dictionary = QDir (fixtures).filePath ("dictionary.txt"); j.device_type = 1; j.workload = 1; j.force = true;
      QVERIFY (QDir ().mkpath (j.directory (temp.path ())));
      Runner runner; QSignalSpy cracked (&runner, &Runner::finished);
      QStringList engine_log; connect (&runner, &Runner::line, &runner, [&engine_log] (const QString &line) { engine_log << line; });
      QVERIFY (runner.start (binary, j.arguments (temp.path ()), QFileInfo (binary).absolutePath ()));
      QTRY_COMPARE_WITH_TIMEOUT (cracked.size (), 1, 120000);
      QVERIFY2 (cracked[0][0].toInt () == 0, qPrintable (engine_log.join ('\n')));
      QFile recovered (j.directory (temp.path ()) + "/results.txt"); QVERIFY (recovered.open (QIODevice::ReadOnly));
      QVERIFY (recovered.readAll ().contains (QByteArray ("gui-fixture-only").toHex ()));
    }
    if (input == "synthetic.cap")
    {
      request.input = file ("malformed.pcap", "not a capture");
      request.output = temp.filePath ("malformed-converted.hashes"); done.clear ();
      QVERIFY (converter.start (request));
      QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 20000);
      QVERIFY (!done[0][0].toBool ()); QVERIFY (!QFileInfo::exists (request.output));
    }
  }
};

QTEST_MAIN (DesktopTest)
#include "test_desktop.moc"
