/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "window.h"
#include "lang.h"

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

  void ui_converter_to_task ()
  {
    const QString fixtures = qEnvironmentVariable ("CAPTURE_FIXTURES");
    if (fixtures.isEmpty ()) QSKIP ("CAPTURE_FIXTURES not supplied");
    QTemporaryDir workspace; Window window (workspace.path ()); window.show ();
    auto *nav = window.findChild<QListWidget *> ("navigation"); nav->setCurrentRow (3);
    const QString output = workspace.filePath ("converted hashes.txt");
    window.findChild<QLineEdit *> ("conversionInput")->setText (QDir (fixtures).filePath ("synthetic.pcapng"));
    window.findChild<QLineEdit *> ("conversionOutput")->setText (output);
    window.findChild<QLineEdit *> ("hcxDirectory")->setText (qEnvironmentVariable ("HCX_DIRECTORY"));
    window.findChild<QCheckBox *> ("useWsl")->setChecked (qEnvironmentVariableIsSet ("HCX_WSL"));
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
    for (int mode : {0, 1, 3, 6, 7, 9}) QTest::newRow (qPrintable (QString::number (mode))) << mode << false;
    QTest::newRow ("mask-file") << 3 << true;
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
  }
};

QTEST_MAIN (DesktopTest)
#include "test_desktop.moc"
