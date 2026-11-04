/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "window.h"
#include "lang.h"

#include <QtTest>
#include <QtWidgets>
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
    j.mask = "?d?d"; j.increment = true; j.minimum = 8; j.maximum = 2; QVERIFY (j.validate ().isEmpty () == false);
    j = job (); j.extra = {"--outfile=/tmp/escape"}; QVERIFY (j.validate ().isEmpty () == false);
    j.extra = {"--encoding-from=UTF-8"}; QVERIFY (j.validate ().isEmpty ());
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
    QVERIFY (logs[0][0].toString ().contains ("TERMINAL_READY"));
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
    const auto array = QJsonDocument::fromJson (logs[0][0].toString ().toUtf8 ()).array ();
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
    if (screenshot.isEmpty () == false) QVERIFY (window.grab ().save (screenshot));
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
  }

  void real_hashcat_dictionary ()
  {
    const QString binary = qEnvironmentVariable ("REAL_HASHCAT");
    if (binary.isEmpty ()) QSKIP ("REAL_HASHCAT not supplied");
    Job j = job (); j.binary = binary; j.device_type = 1; j.workload = 1; j.force = true;
    const QString directory = j.directory (temp.path ()); QVERIFY (QDir ().mkpath (directory));
    Runner runner; QSignalSpy done (&runner, &Runner::finished);
    QVERIFY (runner.start (binary, j.arguments (temp.path ()), QFileInfo (binary).absolutePath ()));
    QTRY_COMPARE_WITH_TIMEOUT (done.size (), 1, 120000);
    QCOMPARE (done[0][0].toInt (), 0);
    QFile results (directory + "/results.txt"); QVERIFY (results.open (QIODevice::ReadOnly));
    QVERIFY (results.readAll ().contains (":74657374"));
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
};

QTEST_MAIN (DesktopTest)
#include "test_desktop.moc"
