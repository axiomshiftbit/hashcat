/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#include "window.h"
#include "lang.h"
#include "pathlist.h"
#include "advancedform.h"
#include "commandbuilder.h"
#include "hashcatinfoparser.h"
#include "telemetry.h"

#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCompleter>
#include <QFileDialog>
#include <QFormLayout>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTableWidget>
#include <QTabWidget>
#include <QTextBrowser>
#include <QVBoxLayout>
#include <QDir>
#include <QDateTime>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QSet>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QUuid>

namespace
{
void words (QObject *object, const char *en, const char *ru)
{
  object->setProperty ("en", QString::fromUtf8 (en));
  object->setProperty ("ru", QString::fromUtf8 (ru));
}

QLabel *label (const char *en, const char *ru)
{
  auto *widget = new QLabel (t (en, ru));
  words (widget, en, ru);
  widget->setWordWrap (true);
  return widget;
}

QPushButton *button (const char *id, const char *en, const char *ru)
{
  auto *widget = new QPushButton (t (en, ru));
  words (widget, en, ru);
  widget->setObjectName (id);
  return widget;
}

QCheckBox *check (const char *id, const char *en, const char *ru)
{
  auto *widget = new QCheckBox (t (en, ru));
  words (widget, en, ru);
  widget->setObjectName (id);
  return widget;
}

QLineEdit *edit (const char *id)
{
  auto *widget = new QLineEdit;
  widget->setObjectName (id);
  return widget;
}

QSpinBox *number (const char *id, int min, int max, int value)
{
  auto *widget = new QSpinBox;
  widget->setObjectName (id);
  widget->setRange (min, max);
  widget->setValue (value);
  return widget;
}

void choice (QComboBox *combo, int value, const char *en, const char *ru)
{
  combo->addItem (t (en, ru), value);
  const int row = combo->count () - 1;
  combo->setItemData (row, QString::fromUtf8 (en), Qt::UserRole + 1);
  combo->setItemData (row, QString::fromUtf8 (ru), Qt::UserRole + 2);
}

QPlainTextEdit *output (const char *id)
{
  auto *widget = new QPlainTextEdit;
  widget->setObjectName (id);
  widget->setReadOnly (true);
  widget->setMaximumBlockCount (3000);
  widget->setFont (QFontDatabase::systemFont (QFontDatabase::FixedFont));
  return widget;
}

QWidget *page (QVBoxLayout **layout, const char *en, const char *ru)
{
  auto *widget = new QWidget;
  *layout = new QVBoxLayout (widget);
  (*layout)->setContentsMargins (28, 22, 28, 22);
  (*layout)->setSpacing (14);
  auto *title = label (en, ru);
  title->setProperty ("heading", true);
  (*layout)->addWidget (title);
  return widget;
}

void row (QFormLayout *form, const char *en, const char *ru, QWidget *widget)
{
  form->addRow (label (en, ru), widget);
}

QStringList lines (const QString &text)
{
  QStringList result;
  for (const QString &line : text.split ('\n'))
  {
    if (line.trimmed ().isEmpty () == false) result << line.trimmed ();
  }
  return result;
}
}

Window::Window (const QString &data_directory, QWidget *parent)
  : QMainWindow (parent), root (data_directory), runner (this), converter (this), extractor (this)
{
  QDir ().mkpath (root);
  setWindowTitle ("Hashcat Desktop");
  resize (1260, 860);
  setMinimumSize (950, 650);
  build ();
  load ();
  retranslate ();
  refresh_form ();
  refresh_jobs ();
  connect (&runner, &Runner::line, this, &Window::append_log);
  connect (&runner, &Runner::status, this, &Window::set_status);
  connect (&runner, &Runner::started, this, &Window::refresh_controls);
  connect (&runner, &Runner::finished, this, &Window::finished);
  probe.setProcessChannelMode (QProcess::MergedChannels);
  probe_timer.setSingleShot (true);
  connect (&probe_timer, &QTimer::timeout, this, [this] { probe.kill (); append_log (t ("Information request timed out.", "Истекло время запроса информации.")); });
  connect (&probe, &QProcess::readyReadStandardOutput, this, [this]
  {
    probe_output += probe.readAllStandardOutput ();
    if (probe_output.size () > 8 * 1024 * 1024) probe.kill ();
  });
  connect (&probe, &QProcess::errorOccurred, this, [this] (QProcess::ProcessError error)
  {
    if (error == QProcess::FailedToStart) { probe_timer.stop (); pending_restore = -1; fail (probe.errorString ()); refresh_controls (); }
  });
  connect (&probe, qOverload<int, QProcess::ExitStatus> (&QProcess::finished), this, [this] (int code, QProcess::ExitStatus)
  {
    probe_timer.stop ();
    probe_output += probe.readAllStandardOutput ();
    if (probe.arguments ().contains ("--machine-readable"))
    {
      QMap<quint32, QString> modes;
      if (code == 0 && HashcatInfoParser::parseExampleHashes (QString::fromUtf8 (probe_output), modes))
      {
        auto *combo = get<QComboBox> ("hashMode");
        const QString previous = combo->currentText ();
        combo->clear ();
        for (auto it = modes.cbegin (); it != modes.cend (); ++it) combo->addItem (it.value (), it.key ());
        combo->setEditText (previous);
      }
    }
    else if (probe_modes && (code == 0))
    {
      help_text = QString::fromUtf8 (probe_output);
      modern_restore = help_text.contains ("--restore-position");
      get<QPlainTextEdit> ("cliHelp")->setPlainText (help_text);
      auto *combo = get<QComboBox> ("hashMode");
      const QString previous = combo->currentText ();
      const auto modes = parse_modes (probe_output);
      if (modes.isEmpty () == false)
      {
        combo->clear ();
        for (const auto &mode : modes) combo->addItem (QString::number (mode.first) + " | " + mode.second, mode.first);
        combo->setEditText (previous);
      }
      statusBar ()->showMessage (t ("Hashcat help and modes loaded.", "Справка и типы хешей Hashcat загружены."), 8000);
      if (pending_restore < 0) QTimer::singleShot (0, this, [this]
      {
        if (!runner.busy ()) run_probe ({"--example-hashes", "--machine-readable"});
      });
    }
    else
    {
      if (probe_modes) { probe.setProperty ("binary", QString ()); modern_restore = false; }
      get<QPlainTextEdit> ("deviceInfo")->setPlainText (QString::fromUtf8 (probe_output));
      get<QTabWidget> ("detailsTabs")->setCurrentIndex (2);
      get<QListWidget> ("navigation")->setCurrentRow (0);
    }
    refresh_controls ();
    if (pending_restore >= 0)
    {
      const int index = pending_restore;
      pending_restore = -1;
      if (code == 0) start_job (index, true);
      else fail (t ("Cannot determine restore support. Check the engine help.", "Не удалось определить способ восстановления. Проверьте справку движка."));
    }
  });
  connect (&converter, &Converter::log, this, [this] (const QString &text) { get<QPlainTextEdit> ("conversionLog")->appendPlainText (text); });
  connect (&converter, &Converter::finished, this, [this] (bool success, const QString &path, int count)
  {
    get<QPushButton> ("convert")->setEnabled (true);
    get<QPushButton> ("cancelConversion")->setEnabled (false);
    get<QPushButton> ("useConversion")->setEnabled (success);
    if (success)
    {
      get<QLineEdit> ("conversionOutput")->setText (path);
      get<QPushButton> ("useConversion")->setProperty ("outputPath", path);
      get<QPlainTextEdit> ("conversionLog")->appendPlainText (t ("Saved records: ", "Сохранено записей: ") + QString::number (count));
    }
  });
}

void Window::build ()
{
  setStyleSheet (R"(
    QMainWindow, QWidget { background:#080c19; color:#e4eaf3; font-size:13px; }
    QLabel[heading="true"] { font-size:25px; font-weight:600; color:#ffffff; }
    QLabel[metric="true"] { font-size:24px; font-weight:600; color:#a5b4fc; padding:10px; background:#111a2c; border-radius:7px; }
    QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextBrowser { background:#111a2c; border:1px solid #334359; border-radius:5px; padding:7px; selection-background-color:#4f46a5; }
    QLineEdit:focus, QPlainTextEdit:focus { border:1px solid #a5b4fc; }
    QPushButton { background:#1c2540; border:1px solid #3a506a; border-radius:5px; padding:8px 13px; }
    QPushButton:hover { background:#303d62; }
    QPushButton[primary="true"] { background:#818cf8; color:#080c19; font-weight:600; border:0; }
    QPushButton:disabled { color:#6a7b90; background:#18212e; border-color:#283345; }
    QListWidget#navigation { background:#070b18; border:0; font-size:14px; padding:10px; }
    QListWidget#navigation::item { padding:14px 10px; margin:3px; border-radius:5px; }
    QListWidget#navigation::item:selected { background:#24204e; color:#a5b4fc; }
    QTableWidget { background:#0b1122; alternate-background-color:#1b2737; border:1px solid #2b3b50; gridline-color:#28384b; }
    QHeaderView::section { background:#243246; padding:8px; border:0; font-weight:600; }
    QTableWidget::item:selected { background:#285766; }
    QTabWidget::pane { border:1px solid #2b3b50; }
    QTabBar::tab { background:#182434; padding:9px 16px; }
    QTabBar::tab:selected { background:#294558; color:#6ae8cd; }
    QProgressBar { background:#1c2b3c; border:0; border-radius:5px; min-height:20px; text-align:center; }
    QProgressBar::chunk { background:#6366f1; border-radius:5px; }
    QGroupBox { border:1px solid #334359; border-radius:6px; margin-top:13px; padding-top:14px; }
    QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 5px; }
    QScrollArea { border:0; } QToolTip { background:#e4eaf3; color:#080c19; padding:5px; }
  )");
  auto *container = new QWidget;
  auto *outer = new QVBoxLayout (container);
  outer->setContentsMargins (0, 0, 0, 0);
  auto *header = new QHBoxLayout;
  header->setContentsMargins (22, 14, 22, 14);
  auto *brand = new QLabel ("HC  /  HASHCAT DESKTOP");
  brand->setStyleSheet ("font-size:18px;font-weight:700;color:#a5b4fc");
  header->addWidget (brand);
  header->addStretch ();
  header->addWidget (label ("Engine", "Движок"));
  auto *binary = path_field ("binary");
  binary->setMinimumWidth (330);
  header->addWidget (binary);
  auto *detect = button ("loadHelp", "Load modes", "Загрузить типы");
  header->addWidget (detect);
  connect (detect, &QPushButton::clicked, this, [this] { run_probe ({"-hh"}, true); });
  auto *language = new QComboBox;
  language->setObjectName ("language");
  language->addItem ("Русский", "ru"); language->addItem ("English", "en");
  header->addWidget (language);
  outer->addLayout (header);
  auto *body = new QHBoxLayout;
  body->setSpacing (0);
  auto *navigation = new QListWidget;
  navigation->setObjectName ("navigation");
  navigation->setFixedWidth (180);
  navigation->addItems ({"", "", "", "", ""});
  auto *pages = new QStackedWidget;
  pages->setObjectName ("pages");
  pages->addWidget (dashboard ()); pages->addWidget (editor ()); pages->addWidget (console_page ());
  pages->addWidget (converter_page ()); pages->addWidget (help_page ());
  body->addWidget (navigation); body->addWidget (pages, 1); outer->addLayout (body, 1);
  setCentralWidget (container);
  connect (navigation, &QListWidget::currentRowChanged, pages, &QStackedWidget::setCurrentIndex);
  navigation->setCurrentRow (0);
  connect (language, &QComboBox::currentIndexChanged, this, [this, language]
  {
    qApp->setProperty ("language", language->currentData ().toString ()); retranslate (); save ();
  });
  connect (get<QLineEdit> ("binary"), &QLineEdit::textChanged, this, [this] { modern_restore = false; probe.setProperty ("binary", QString ()); refresh_form (); });
  for (auto *field : get<QWidget> ("form")->findChildren<QLineEdit *> ()) connect (field, &QLineEdit::textChanged, this, &Window::refresh_form);
  for (auto *field : get<QWidget> ("form")->findChildren<QComboBox *> ()) connect (field, &QComboBox::currentTextChanged, this, &Window::refresh_form);
  for (auto *field : get<QWidget> ("form")->findChildren<QSpinBox *> ()) connect (field, &QSpinBox::valueChanged, this, &Window::refresh_form);
  for (auto *field : get<QWidget> ("form")->findChildren<QCheckBox *> ()) connect (field, &QCheckBox::toggled, this, &Window::refresh_form);
  for (auto *field : get<QWidget> ("form")->findChildren<QPlainTextEdit *> ())
  {
    if (field->isReadOnly () == false) connect (field, &QPlainTextEdit::textChanged, this, &Window::refresh_form);
  }
}

QWidget *Window::path_field (const char *name, const bool directory, const bool save_file)
{
  auto *widget = new QWidget;
  auto *layout = new QHBoxLayout (widget);
  layout->setContentsMargins (0, 0, 0, 0);
  auto *field = edit (name);
  layout->addWidget (field, 1);
  auto *browse = button (qPrintable (QString::fromLatin1 (name) + "Browse"), "Browse", "Обзор");
  layout->addWidget (browse);
  connect (browse, &QPushButton::clicked, this, [this, field, directory, save_file]
  {
    QString path;
    if (directory) path = QFileDialog::getExistingDirectory (this, t ("Select directory", "Выберите каталог"), field->text ());
    else if (save_file) path = QFileDialog::getSaveFileName (this, t ("New output file", "Новый файл результата"), field->text ());
    else path = QFileDialog::getOpenFileName (this, t ("Select file", "Выберите файл"), field->text ());
    if (path.isEmpty () == false) field->setText (QDir::toNativeSeparators (path));
  });
  return widget;
}

QWidget *Window::dashboard ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "Your recovery workspace", "Рабочее пространство");
  layout->addWidget (label ("One engine. A clear queue. Live progress.", "Один движок. Очередь задач. Прогресс в реальном времени."));
  auto *metrics = new QHBoxLayout;
  const char *ids[] {"speed", "recovered", "eta"};
  const char *en[] {"Speed", "Recovered", "Estimated finish"};
  const char *ru[] {"Скорость", "Восстановлено", "Ожидаемое завершение"};
  for (int i = 0; i < 3; ++i)
  {
    auto *column = new QVBoxLayout;
    column->addWidget (label (en[i], ru[i]));
    auto *value = new QLabel ("—"); value->setObjectName (ids[i]); value->setProperty ("metric", true);
    column->addWidget (value); metrics->addLayout (column, 1);
  }
  layout->addLayout (metrics);
  auto *progress = new QProgressBar;
  progress->setObjectName ("progress"); progress->setRange (0, 1000); progress->setValue (0);
  layout->addWidget (progress);
  auto *telemetry = new Telemetry; telemetry->setObjectName ("telemetry");
  layout->addWidget (telemetry);
  auto *table = new QTableWidget (0, 4);
  table->setObjectName ("jobs"); table->setSelectionBehavior (QAbstractItemView::SelectRows);
  table->setSelectionMode (QAbstractItemView::SingleSelection); table->setEditTriggers (QAbstractItemView::NoEditTriggers);
  table->setAlternatingRowColors (true); table->verticalHeader ()->hide ();
  table->horizontalHeader ()->setSectionResizeMode (QHeaderView::ResizeToContents);
  table->horizontalHeader ()->setSectionResizeMode (0, QHeaderView::Stretch);
  table->setMinimumHeight (150);
  layout->addWidget (table, 2);
  auto *actions = new QHBoxLayout;
  auto *run = button ("runSelected", "Start", "Запустить"); run->setProperty ("primary", true);
  auto *restore = button ("restore", "Restore", "Восстановить сессию");
  auto *duplicate = button ("duplicate", "Copy to form", "В форму");
  auto *remove = button ("removeJob", "Remove", "Убрать");
  auto *auto_next = check ("autoNext", "Run queue", "Выполнять очередь");
  actions->addWidget (run); actions->addWidget (restore); actions->addWidget (duplicate); actions->addWidget (remove);
  actions->addStretch (); actions->addWidget (auto_next); layout->addLayout (actions);
  auto *control = new QHBoxLayout;
  const char *control_ids[] {"pause", "resume", "checkpoint", "stop"};
  const char *control_en[] {"Pause", "Resume", "Stop at checkpoint", "Stop"};
  const char *control_ru[] {"Пауза", "Продолжить", "Остановить на точке", "Остановить"};
  const char keys[] {'p', 'r', 'c', 'q'};
  for (int i = 0; i < 4; ++i)
  {
    auto *b = button (control_ids[i], control_en[i], control_ru[i]); control->addWidget (b);
    const char key = keys[i];
    connect (b, &QPushButton::clicked, this, [this, key]
    {
      if (key == 'q') { stop_requested = true; runner.stop (); }
      else if (runner.command (key))
      {
        if (key == 'c') stop_requested = true;
        statusBar ()->showMessage (t ("Command sent. Waiting for engine status.", "Команда отправлена. Ожидается статус движка."), 5000);
      }
    });
  }
  layout->addLayout (control);
  auto *tabs = new QTabWidget;
  tabs->setObjectName ("detailsTabs");
  tabs->addTab (output ("log"), "");
  auto *result_page = new QWidget;
  auto *results_layout = new QVBoxLayout (result_page);
  auto *results = new QTableWidget (0, 2);
  results->setObjectName ("results"); results->setEditTriggers (QAbstractItemView::NoEditTriggers);
  results->horizontalHeader ()->setSectionResizeMode (QHeaderView::Stretch);
  results_layout->addWidget (results);
  auto *export_button = button ("exportResults", "Export complete results (hash:hex)", "Экспорт всех результатов (хеш:hex)");
  results_layout->addWidget (export_button);
  tabs->addTab (result_page, "");
  tabs->addTab (output ("deviceInfo"), "");
  layout->addWidget (tabs, 3);
  connect (table, &QTableWidget::itemSelectionChanged, this, [this] { refresh_controls (); refresh_results (); });
  connect (run, &QPushButton::clicked, this, [this] { start_job (selected ()); });
  connect (restore, &QPushButton::clicked, this, [this] { start_job (selected (), true); });
  connect (duplicate, &QPushButton::clicked, this, [this]
  {
    const int index = selected (); if (index < 0) return;
    set_form (jobs[index]); get<QListWidget> ("navigation")->setCurrentRow (1);
  });
  connect (remove, &QPushButton::clicked, this, [this]
  {
    const int index = selected (); if ((index < 0) || runner.busy ()) return;
    jobs.removeAt (index); save (); refresh_jobs ();
  });
  connect (export_button, &QPushButton::clicked, this, [this]
  {
    const int index = selected (); if (index < 0) return;
    const QString destination = QFileDialog::getSaveFileName (this, t ("Export results", "Экспорт результатов"), "results.txt");
    if (destination.isEmpty ()) return;
    QFile input (jobs[index].directory (root) + "/results.txt");
    QSaveFile out (destination);
    if ((input.open (QIODevice::ReadOnly) == false) || (out.open (QIODevice::WriteOnly) == false)) { fail (t ("Cannot open result files.", "Не удалось открыть файлы результатов.")); return; }
    out.setPermissions (QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    while (input.atEnd () == false)
    {
      const auto bytes = input.read (65536);
      if (bytes.isEmpty () || (out.write (bytes) != bytes.size ())) { fail (out.errorString ()); return; }
    }
    if (out.commit () == false) fail (out.errorString ());
  });
  auto *scroll = new QScrollArea; scroll->setWidgetResizable (true); scroll->setWidget (widget);
  return scroll;
}

QWidget *Window::editor ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "New task", "Новая задача");
  auto *scroll = new QScrollArea; scroll->setWidgetResizable (true);
  auto *form_widget = new QWidget; form_widget->setObjectName ("form");
  auto *form = new QFormLayout (form_widget); form->setSpacing (12); form->setFieldGrowthPolicy (QFormLayout::AllNonFixedFieldsGrow);
  row (form, "Task name", "Название", edit ("jobName"));
  row (form, "Hash file", "Файл хешей", path_field ("hashFile"));
  auto *mode = new QComboBox; mode->setObjectName ("hashMode"); mode->setEditable (true);
  const QList<QPair<int, QString>> defaults {{0, "MD5"}, {100, "SHA-1"}, {1400, "SHA-256"}, {1700, "SHA-512"}, {1000, "NTLM"}, {3200, "bcrypt"}, {22000, "WPA-PBKDF2-PMKID+EAPOL"}, {4800, "EAP-MD5"}, {5500, "NetNTLMv1 / LEAP"}, {16100, "TACACS+"}};
  for (const auto &item : defaults) mode->addItem (QString::number (item.first) + " | " + item.second, item.first);
  mode->completer ()->setFilterMode (Qt::MatchContains); mode->completer ()->setCompletionMode (QCompleter::PopupCompletion);
  row (form, "Hash mode / search / number", "Тип хеша / поиск / номер", mode);
  auto *attack = new QComboBox; attack->setObjectName ("attack");
  choice (attack, 0, "0 · Dictionary", "0 · Словарь"); choice (attack, 1, "1 · Combinator", "1 · Комбинация словарей");
  choice (attack, 3, "3 · Mask", "3 · Маска"); choice (attack, 6, "6 · Dictionary + mask", "6 · Словарь + маска");
  choice (attack, 7, "7 · Mask + dictionary", "7 · Маска + словарь"); choice (attack, 9, "9 · Association", "9 · Ассоциация");
  choice (attack, 4, "4 · PCFG (Hashcat 8)", "4 · PCFG (Hashcat 8)");
  choice (attack, 5, "5 · Table (Hashcat 8)", "5 · Таблица (Hashcat 8)");
  choice (attack, 8, "8 · Generic feed (Hashcat 8)", "8 · Генератор (Hashcat 8)");
  choice (attack, 12, "12 · Word-position hybrid (Hashcat 8)", "12 · Гибрид с позицией слова (Hashcat 8)");
  row (form, "Attack", "Способ подбора", attack);
  auto *wordlists = new PathList (true); wordlists->setObjectName ("wordlists");
  row (form, "Dictionaries / folders (checked rows, in order)", "Словари / каталоги (отмеченные строки по порядку)", wordlists);
  connect (wordlists, &PathList::changed, this, &Window::refresh_form);
  row (form, "Mask or .hcmask file", "Маска или файл .hcmask", path_field ("mask"));
  auto *hint = label ("?l lower · ?u upper · ?d digit · ?s symbol · ?a all · ?? literal ?. Example: ?u?l?l?l?d?d", "?l строчные · ?u прописные · ?d цифры · ?s знаки · ?a все · ?? знак ?. Пример: ?u?l?l?l?d?d");
  form->addRow (hint);
  auto *rules = new PathList (false); rules->setObjectName ("rules");
  row (form, "Rule files (checked rows)", "Файлы правил (отмеченные строки)", rules);
  connect (rules, &PathList::changed, this, &Window::refresh_form);
  auto *sets = new QWidget; auto *sets_layout = new QHBoxLayout (sets); sets_layout->setContentsMargins (0, 0, 0, 0);
  for (int i = 1; i <= 4; ++i)
  {
    sets_layout->addWidget (new QLabel ("?" + QString::number (i)));
    sets_layout->addWidget (edit (qPrintable ("charset" + QString::number (i))));
  }
  row (form, "Custom character sets", "Свои наборы символов", sets);
  auto *length = new QWidget; auto *length_layout = new QHBoxLayout (length); length_layout->setContentsMargins (0, 0, 0, 0);
  length_layout->addWidget (check ("increment", "Increment length", "Наращивать длину"));
  length_layout->addWidget (number ("minimum", 1, 256, 1)); length_layout->addWidget (new QLabel ("…"));
  length_layout->addWidget (number ("maximum", 1, 256, 8)); row (form, "Length range", "Диапазон длины", length);
  auto *type = new QComboBox; type->setObjectName ("deviceType");
  choice (type, 0, "Automatic", "Автоматически"); choice (type, 1, "CPU", "CPU"); choice (type, 2, "GPU", "GPU"); choice (type, 3, "CPU + GPU", "CPU + GPU");
  row (form, "OpenCL device types", "Типы устройств OpenCL", type);
  row (form, "Device IDs (optional, e.g. 1,2)", "Номера устройств (например 1,2)", edit ("devices"));
  auto *workload = new QComboBox; workload->setObjectName ("workload");
  choice (workload, 1, "1 · Low", "1 · Низкая"); choice (workload, 2, "2 · Default", "2 · Обычная");
  choice (workload, 3, "3 · High", "3 · Высокая"); choice (workload, 4, "4 · Headless", "4 · Максимальная"); workload->setCurrentIndex (1);
  row (form, "Workload", "Нагрузка", workload);
  row (form, "Abort temperature (°C)", "Температура остановки (°C)", number ("temperature", 50, 100, 85));
  row (form, "Time limit (s), 0 = unlimited", "Лимит (сек.), 0 = без ограничения", number ("runtime", 0, 8640000, 0));
  form->addRow (check ("optimized", "Optimized kernels (-O): shorter maximum passwords", "Оптимизированные ядра (-O): ограничение длины пароля"));
  form->addRow (check ("username", "Input contains username:hash", "Входной файл содержит имя:хеш"));
  form->addRow (check ("force", "Ignore backend warnings (--force)", "Игнорировать предупреждения движка (--force)"));
  auto *advanced = new AdvancedForm; advanced->setObjectName ("advanced");
  form->addRow (label ("Extended options and Hashcat 8 feeds", "Расширенные параметры и генераторы Hashcat 8"));
  form->addRow (advanced);
  connect (advanced, &AdvancedForm::changed, this, &Window::refresh_form);
  auto *extra = new QPlainTextEdit; extra->setObjectName ("extra"); extra->setMaximumHeight (65);
  row (form, "Additional options (one per line)", "Доп. параметры (по одному на строку)", extra);
  form->addRow (label ("For every CLI command, unusual attacks and unrestricted options, use the CLI page. Parameters here use --name=value.", "Все команды CLI, другие режимы и произвольные параметры доступны на вкладке «Команды». Здесь параметры задаются как --имя=значение."));
  scroll->setWidget (form_widget); layout->addWidget (scroll, 1);
  auto *preview = output ("preview"); preview->setMaximumHeight (70); layout->addWidget (preview);
  auto *error = new QLabel; error->setObjectName ("validation"); error->setWordWrap (true); error->setStyleSheet ("color:#eebc77"); layout->addWidget (error);
  auto *actions = new QHBoxLayout;
  auto *load = button ("loadProfile", "Load profile", "Загрузить профиль");
  auto *save_profile = button ("saveProfile", "Save profile", "Сохранить профиль");
  auto *add = button ("addJob", "Add to queue", "В очередь");
  auto *start = button ("startNow", "Start now", "Запустить сейчас"); start->setProperty ("primary", true);
  actions->addWidget (load); actions->addWidget (save_profile); actions->addStretch (); actions->addWidget (add); actions->addWidget (start); layout->addLayout (actions);
  connect (add, &QPushButton::clicked, this, [this] { add_job (false); });
  connect (start, &QPushButton::clicked, this, [this] { add_job (true); });
  connect (save_profile, &QPushButton::clicked, this, [this]
  {
    const QString path = QFileDialog::getSaveFileName (this, t ("Save profile", "Сохранить профиль"), "profile.json", "JSON (*.json)");
    if (path.isEmpty ()) return;
    QString error; if (save_json (path, form_job ().json (), &error) == false) fail (error);
  });
  connect (load, &QPushButton::clicked, this, [this]
  {
    const QString path = QFileDialog::getOpenFileName (this, t ("Load profile", "Загрузить профиль"), {}, "JSON (*.json)");
    if (path.isEmpty ()) return;
    QFile file (path); if ((file.open (QIODevice::ReadOnly) == false) || (file.size () > 1048576)) { fail (t ("Cannot read profile.", "Не удалось прочитать профиль.")); return; }
    const auto doc = QJsonDocument::fromJson (file.readAll ());
    if (doc.isObject () == false) { fail (t ("Invalid JSON profile.", "Неверный JSON-профиль.")); return; }
    set_form (Job::from_json (doc.object ()));
  });
  return widget;
}

QWidget *Window::console_page ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "All Hashcat commands", "Все команды Hashcat");
  layout->addWidget (label ("Run any command supported by your Hashcat build. Each line is one argument, without shell quoting. A JSON array of strings is also accepted. No shell is used.", "Запускайте любую команду вашей версии Hashcat. Каждая строка — один аргумент, без кавычек оболочки. Можно задать JSON-массив строк. Оболочка не используется."));
  auto *templates = new QHBoxLayout;
  const QList<QPair<QString, QStringList>> examples {{"--help", {"-hh"}}, {"--backend-info", {"-I"}}, {"--benchmark", {"-b", "-m", "0"}}, {"--example-hashes", {"--example-hashes", "-m", "0"}}};
  for (const auto &example : examples)
  {
    auto *b = new QPushButton (example.first); templates->addWidget (b);
    connect (b, &QPushButton::clicked, this, [this, example] { get<QPlainTextEdit> ("arguments")->setPlainText (example.second.join ('\n')); });
  }
  auto *from_form = button ("fromForm", "From task form", "Из формы задачи"); templates->addWidget (from_form);
  layout->addLayout (templates);
  auto *args = new QPlainTextEdit; args->setObjectName ("arguments"); args->setPlainText ("--version");
  args->setFont (QFontDatabase::systemFont (QFontDatabase::FixedFont)); args->setMaximumHeight (230); layout->addWidget (args);
  auto *form = new QFormLayout;
  row (form, "Working directory (empty = engine directory)", "Рабочий каталог (пусто = каталог движка)", path_field ("expertCwd", true)); layout->addLayout (form);
  row (form, "Standard input file (optional, disables keyboard input)", "Файл стандартного ввода (вместо клавиатуры)", path_field ("stdinFile"));
  auto *actions = new QHBoxLayout;
  auto *run = button ("expertRun", "Run command", "Выполнить команду"); run->setProperty ("primary", true);
  auto *stop = button ("expertStop", "Stop", "Остановить");
  actions->addWidget (run); actions->addWidget (stop); actions->addStretch ();
  auto *key = edit ("consoleKeys"); key->setMaximumWidth (150); actions->addWidget (key);
  auto *send = button ("sendKeys", "Send keys", "Отправить клавиши"); actions->addWidget (send);
  layout->addLayout (actions);
  layout->addWidget (label ("Interactive controls: s status · p pause · r resume · c checkpoint · b bypass · f finish · q quit. For prompts, add Enter with the checkbox.", "Управление: s статус · p пауза · r продолжить · c контрольная точка · b пропустить · f завершить · q выход. Для ответа на запрос добавьте Enter флажком."));
  layout->addWidget (check ("sendEnter", "Append Enter", "Добавить Enter"));
  layout->addWidget (output ("consoleOutput"), 1);
  connect (run, &QPushButton::clicked, this, &Window::start_expert);
  connect (stop, &QPushButton::clicked, this, [this] { stop_requested = true; runner.stop (); });
  connect (send, &QPushButton::clicked, this, [this, key]
  {
    const QByteArray bytes = key->text ().toUtf8 ();
    for (const char ch : bytes) runner.command (ch);
    if (get<QCheckBox> ("sendEnter")->isChecked ()) runner.command ('\r');
  });
  connect (from_form, &QPushButton::clicked, this, [this]
  {
    Job job = form_job (); job.id = "cli-" + QUuid::createUuid ().toString (QUuid::Id128);
    const QString directory = job.directory (root);
    QDir ().mkpath (directory);
    QFile::setPermissions (directory, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    get<QPlainTextEdit> ("arguments")->setPlainText (job.arguments (root).join ('\n'));
  });
  return widget;
}

QWidget *Window::converter_page ()
{
  auto *tabs = new QTabWidget; tabs->setObjectName ("converterTabs");
  tabs->addTab (capture_page (), ""); tabs->addTab (extractor_page (), "");
  return tabs;
}

QWidget *Window::extractor_page ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "File to hash", "Из файла в хеш");
  layout->addWidget (label ("Local extractor catalog from Hashcat-Reactor. Install the appropriate John Jumbo tool and its dependencies. Availability and Hashcat compatibility depend on the exact format/version; a catalog entry is not a guarantee of support.", "Каталог локальных конвертеров из Hashcat-Reactor. Установите нужную утилиту John Jumbo и её зависимости. Поддержка зависит от формата и версии; наличие в каталоге не гарантирует совместимость с Hashcat."));
  auto *form = new QFormLayout; layout->addLayout (form);
  auto *kind = new QComboBox; kind->setObjectName ("extractKind"); kind->setEditable (false);
  const auto catalog = Extractor::catalog ();
  for (auto it = catalog.begin (); it != catalog.end (); ++it) kind->addItem (it.key () + " · " + it.value ().toObject ()["name"].toString (), it.key ());
  row (form, "Format / extractor", "Формат / конвертер", kind);
  row (form, "John Jumbo run directory", "Каталог run John Jumbo", path_field ("johnDirectory", true));
  row (form, "Extractor executable or script", "Исполняемый файл или скрипт", path_field ("extractTool"));
  row (form, "Python/Perl (empty = PATH)", "Python/Perl (пусто = PATH)", path_field ("extractInterpreter"));
  auto resolve = [this, kind, catalog]
  {
    const auto item = catalog[kind->currentData ().toString ()].toObject ();
    const QString name = item["name"].toString (), type = item["kind"].toString ();
    QStringList names;
    if (type == "python") names << name + ".py";
    if (type == "perl") names << name + ".pl";
#ifdef Q_OS_WIN
    names << name + ".exe";
#endif
    names << name << name + ".py" << name + ".pl";
    const QString directory = get<QLineEdit> ("johnDirectory")->text ();
    QString found;
    for (const auto &candidate : names)
    {
      const QString path = QDir (directory).filePath (candidate);
      if (QFileInfo (path).isFile ()) { found = QFileInfo (path).absoluteFilePath (); break; }
    }
    get<QLineEdit> ("extractTool")->setText (found);
  };
  connect (kind, &QComboBox::currentIndexChanged, this, resolve);
  connect (widget->findChild<QLineEdit *> ("johnDirectory"), &QLineEdit::textChanged, this, resolve);
  row (form, "Input file", "Исходный файл", path_field ("extractInput"));
  row (form, "New hash file", "Новый файл хешей", path_field ("extractOutput", false, true));
  auto *arguments = new QPlainTextEdit; arguments->setObjectName ("extractArguments"); arguments->setMaximumHeight (65);
  row (form, "Tool arguments, one per line (input is appended)", "Аргументы утилиты по одному на строку (файл добавится в конце)", arguments);
  auto *actions = new QHBoxLayout; layout->addLayout (actions);
  auto *start = button ("extractStart", "Extract and identify", "Извлечь и определить"); start->setProperty ("primary", true);
  auto *cancel = button ("extractCancel", "Cancel", "Отмена"); cancel->setEnabled (false);
  auto *modes = new QComboBox; modes->setObjectName ("extractModes");
  auto *use = button ("extractUse", "Use in new task", "В новую задачу"); use->setEnabled (false);
  actions->addWidget (start); actions->addWidget (cancel); actions->addWidget (modes, 1); actions->addWidget (use);
  layout->addWidget (output ("extractLog"), 1);
  connect (start, &QPushButton::clicked, this, [this, start, cancel, use, modes, arguments]
  {
    Extraction request;
    request.input = get<QLineEdit> ("extractInput")->text (); request.output = get<QLineEdit> ("extractOutput")->text ();
    request.tool = get<QLineEdit> ("extractTool")->text (); request.interpreter = get<QLineEdit> ("extractInterpreter")->text ();
    request.hashcat = get<QLineEdit> ("binary")->text (); request.arguments = arguments->toPlainText ().split ('\n', Qt::SkipEmptyParts);
    use->setEnabled (false); modes->clear (); get<QPlainTextEdit> ("extractLog")->clear ();
    start->setEnabled (false); cancel->setEnabled (true);
    if (!extractor.start (request)) { start->setEnabled (true); cancel->setEnabled (false); }
    save ();
  });
  connect (cancel, &QPushButton::clicked, &extractor, &Extractor::cancel);
  connect (&extractor, &Extractor::log, this, [this] (const QString &text) { get<QPlainTextEdit> ("extractLog")->appendPlainText (text); });
  connect (&extractor, &Extractor::finished, this, [this, start, cancel, use, modes] (bool success, const QString &path, const QList<int> &types)
  {
    start->setEnabled (true); cancel->setEnabled (false); use->setEnabled (success);
    use->setProperty ("outputPath", path);
    for (const int type : types) modes->addItem (QString::number (type), type);
    if (success) get<QPlainTextEdit> ("extractLog")->appendPlainText (t ("Saved. Select the matching hash mode before importing.", "Сохранено. Перед импортом выберите подходящий тип хеша."));
  });
  connect (use, &QPushButton::clicked, this, [this, use, modes]
  {
    get<QLineEdit> ("hashFile")->setText (use->property ("outputPath").toString ());
    get<QComboBox> ("hashMode")->setEditText (modes->currentData ().toString ());
    get<QListWidget> ("navigation")->setCurrentRow (1);
  });
  auto *scroll = new QScrollArea; scroll->setWidgetResizable (true); scroll->setWidget (widget); return scroll;
}

QWidget *Window::capture_page ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "Capture converter", "Конвертер захватов");
  layout->addWidget (label ("Offline extraction using hcxtools, the engine used by hashcat.net. PCAPNG · PCAP · CAP · .gz. Legacy HCCAPX · HCCAP · PMKID (.16800). No capture is uploaded.", "Локальное извлечение через hcxtools — движок конвертера hashcat.net. PCAPNG · PCAP · CAP · .gz. Старые HCCAPX · HCCAP · PMKID (.16800). Захваты никуда не отправляются."));
  auto *form = new QFormLayout; form->setSpacing (14);
  row (form, "Capture / legacy hash file", "Захват / старый файл хешей", path_field ("conversionInput"));
  row (form, "New output file", "Новый файл результата", path_field ("conversionOutput", false, true));
  auto *mode = new QComboBox; mode->setObjectName ("conversionMode");
  mode->addItem ("22000 · WPA/WPA2 PMKID + EAPOL", 22000);
  mode->addItem ("4800 · EAP-MD5", 4800); mode->addItem ("5500 · LEAP / MSCHAPv2", 5500); mode->addItem ("16100 · TACACS+", 16100);
  row (form, "Extract hash type", "Извлечь тип хеша", mode);
  row (form, "hcxtools directory (empty = PATH)", "Каталог hcxtools (пусто = PATH)", path_field ("hcxDirectory", true));
  auto *wsl = check ("useWsl", "Use hcxtools in the default WSL distribution (Windows)", "Использовать hcxtools в основной WSL-системе (Windows)");
#ifdef Q_OS_WIN
  wsl->setChecked (true);
#else
  wsl->setEnabled (false);
#endif
  form->addRow (wsl); layout->addLayout (form);
  layout->addWidget (label ("Linux: install hcxtools. Windows: install WSL with a Linux distribution, then install hcxtools there. Legacy formats additionally need hcxhash2cap. The converter keeps default extraction settings, matching the website.", "Linux: установите hcxtools. Windows: установите WSL с Linux, затем hcxtools внутри неё. Для старых форматов нужен также hcxhash2cap. Используются стандартные настройки извлечения, как на сайте."));
  auto *actions = new QHBoxLayout;
  auto *convert = button ("convert", "Convert locally", "Конвертировать локально"); convert->setProperty ("primary", true);
  auto *cancel = button ("cancelConversion", "Cancel", "Отмена"); cancel->setEnabled (false);
  auto *use = button ("useConversion", "Use in new task", "В новую задачу"); use->setEnabled (false);
  actions->addWidget (convert); actions->addWidget (cancel); actions->addStretch (); actions->addWidget (use); layout->addLayout (actions);
  layout->addWidget (output ("conversionLog"), 1);
  connect (convert, &QPushButton::clicked, this, [this, convert, cancel]
  {
    Conversion request;
    request.input = get<QLineEdit> ("conversionInput")->text ();
    request.output = get<QLineEdit> ("conversionOutput")->text ();
    request.tools_directory = get<QLineEdit> ("hcxDirectory")->text ();
    request.mode = get<QComboBox> ("conversionMode")->currentData ().toInt ();
    request.wsl = get<QCheckBox> ("useWsl")->isChecked ();
    get<QPushButton> ("useConversion")->setProperty ("hashMode", request.mode);
    get<QPlainTextEdit> ("conversionLog")->clear ();
    get<QPushButton> ("useConversion")->setEnabled (false);
    convert->setEnabled (false); cancel->setEnabled (true);
    if (converter.start (request) == false) { convert->setEnabled (true); cancel->setEnabled (false); }
    save ();
  });
  connect (cancel, &QPushButton::clicked, &converter, &Converter::cancel);
  connect (use, &QPushButton::clicked, this, [this]
  {
    get<QLineEdit> ("hashFile")->setText (get<QPushButton> ("useConversion")->property ("outputPath").toString ());
    get<QComboBox> ("hashMode")->setEditText (get<QPushButton> ("useConversion")->property ("hashMode").toString ());
    get<QListWidget> ("navigation")->setCurrentRow (1);
  });
  return widget;
}

QWidget *Window::help_page ()
{
  QVBoxLayout *layout;
  auto *widget = page (&layout, "Guide & command reference", "Руководство и справочник команд");
  auto *tabs = new QTabWidget; tabs->setObjectName ("helpTabs");
  auto *guide = new QTextBrowser; guide->setObjectName ("guide"); guide->setOpenExternalLinks (true);
  tabs->addTab (guide, "");
  auto *cli = new QWidget; auto *cli_layout = new QVBoxLayout (cli);
  auto *search_row = new QHBoxLayout;
  auto *search = edit ("helpSearch"); search_row->addWidget (search);
  auto *find = button ("findHelp", "Find next", "Найти далее"); search_row->addWidget (find);
  auto *reload = button ("refreshHelp", "Read hashcat -hh", "Прочитать hashcat -hh"); search_row->addWidget (reload);
  cli_layout->addLayout (search_row); cli_layout->addWidget (output ("cliHelp"), 1); tabs->addTab (cli, "");
  layout->addWidget (tabs, 1);
  auto *devices = button ("probeDevices", "Inspect compute devices", "Проверить вычислительные устройства"); layout->addWidget (devices);
  connect (devices, &QPushButton::clicked, this, [this] { run_probe ({"-I"}); });
  connect (reload, &QPushButton::clicked, this, [this] { run_probe ({"-hh"}, true); });
  connect (find, &QPushButton::clicked, this, [this, search]
  {
    auto *text = get<QPlainTextEdit> ("cliHelp");
    if (text->find (search->text ()) == false) { text->moveCursor (QTextCursor::Start); text->find (search->text ()); }
  });
  connect (search, &QLineEdit::returnPressed, find, &QPushButton::click);
  return widget;
}

void Window::retranslate ()
{
  for (auto *list : findChildren<PathList *> ()) list->retranslate ();
  get<AdvancedForm> ("advanced")->retranslate ();
  get<Telemetry> ("telemetry")->update ();
  get<QTabWidget> ("converterTabs")->setTabText (0, t ("Wi-Fi / captures", "Wi-Fi / захваты"));
  get<QTabWidget> ("converterTabs")->setTabText (1, t ("Archives / documents / other files", "Архивы / документы / другие файлы"));
  const char *property = russian () ? "ru" : "en";
  for (auto *object : findChildren<QObject *> ())
  {
    const QString text = object->property (property).toString ();
    if (text.isEmpty ()) continue;
    if (auto *value = qobject_cast<QLabel *> (object)) value->setText (text);
    else if (auto *value = qobject_cast<QAbstractButton *> (object)) value->setText (text);
  }
  for (auto *combo : findChildren<QComboBox *> ())
  {
    const QSignalBlocker blocker (combo);
    for (int i = 0; i < combo->count (); ++i)
    {
      const QString text = combo->itemData (i, russian () ? Qt::UserRole + 2 : Qt::UserRole + 1).toString ();
      if (text.isEmpty () == false) combo->setItemText (i, text);
    }
  }
  auto *navigation = get<QListWidget> ("navigation");
  const QStringList names {t ("Workspace", "Задачи"), t ("New task", "Новая задача"), t ("Commands", "Команды"), t ("Converter", "Конвертер"), t ("Help", "Справка")};
  for (int i = 0; i < names.size (); ++i) navigation->item (i)->setText (names[i]);
  get<QTableWidget> ("jobs")->setHorizontalHeaderLabels ({t ("Task", "Задача"), t ("Hash mode", "Тип хеша"), t ("Attack", "Режим"), t ("State", "Состояние")});
  get<QTableWidget> ("results")->setHorizontalHeaderLabels ({t ("Hash", "Хеш"), t ("Recovered value (UTF-8)", "Восстановленное значение (UTF-8)")});
  auto *details = get<QTabWidget> ("detailsTabs");
  details->setTabText (0, t ("Log", "Журнал")); details->setTabText (1, t ("Results", "Результаты")); details->setTabText (2, t ("Devices", "Устройства"));
  get<QTabWidget> ("helpTabs")->setTabText (0, t ("Getting started", "Как пользоваться"));
  get<QTabWidget> ("helpTabs")->setTabText (1, t ("Full CLI reference", "Полная справка CLI"));
  get<QTextBrowser> ("guide")->setHtml (t (
    "<h2>From a file to a repeatable task</h2><ol><li>Select hashcat.exe (Windows) or hashcat (Linux) at the top. Keep its complete distribution, including modules and OpenCL files. Install the GPU vendor's compute driver; CPU testing can use PoCL on Linux.</li><li>Click <b>Load modes</b> to read the installed engine's complete help and supported hash types. The number field also accepts any mode directly.</li><li>Open <b>New task</b>, choose the input hashes and the correct mode. The forms support all ten Hashcat 8 modes. Select and reorder checked dictionaries/rules. Profiles keep unchecked rows. Modes 4/5/8/12 require Hashcat 8; their settings are in the extended tabs. Mode 12 needs one ?w and optionally one ?q after it, with two dictionaries; increment is not supported. Association mode requires a matching dictionary line for each hash.</li><li>Add the task to the queue or start it immediately. Only one task runs at a time. Queue processing continues after success or exhaustion, but stops on errors and manual interruptions.</li><li>Watch speed, recovered count, device telemetry and estimated finish. Pause/resume waits for real engine status. A checkpoint stop waits until Hashcat can save its state. Stop allows eight seconds for a graceful exit before killing an unresponsive process.</li></ol>"
    "<h3>Sessions and results</h3><p>Each task has its own restore file, potfile and results under the application data directory. Restore uses the same task settings and files. Hashcat 8 uses --restore-position; earlier versions use --restore. Load the engine help before restoring. Interrupted tasks never restart automatically on app launch. Copy a task to the form to change its settings and create a new task. Removing a queue entry preserves its files.</p><p>The results table displays at most 2,000 entries. Export copies the complete hash:hex file. Hex preserves arbitrary bytes and delimiters; UTF-8 display may show replacement characters for non-text passwords. Profiles and queue metadata contain paths and settings. Logs stay in memory and are bounded. Files are stored on your computer.</p>"
    "<h3>Every CLI command</h3><p>The <b>Commands</b> page accepts every argument supported by your engine, including modes 4/5/8/12, rules, devices, benchmarks, --identify, --show, --left, --keyspace, --stdout, brain and new options. Enter one argument per line, with no surrounding shell quotes, or a JSON string array. Paths with spaces are a single argument. Shell pipes and redirection are not interpreted. Use Hashcat's file options. Interactive prompts accept text and Enter. Read the actual installed help in the second tab and search for option names.</p><p>CLI mode runs exactly your arguments: session files, output files and destructive flags such as --remove remain under your control. It does not add the managed queue's status/output options. Use <b>From task form</b> for an editable starting point.</p>"
    "<h3>Preparing hashes</h3><p>The official online converter accepts PCAPNG, PCAP and CAP for WPA/WPA2 mode 22000. This app uses the same hcxpcapngtool locally, adds gzip and legacy HCCAP/HCCAPX/16800 conversion, and can extract EAP-MD5 (4800), LEAP/MSCHAPv2 (5500) and TACACS+ (16100). A capture without the required exchange produces no hashes. Windows uses hcxtools inside WSL; Linux runs it directly.</p><p>Encrypted ZIP/7z/RAR archives, PDF/Office documents, KeePass databases and disk containers also require format-specific extraction. They are NOT accepted by the website's Wi-Fi converter. Open the second converter tab and select an installed John Jumbo extractor, its input file, a new output path and, for scripts, Python or Perl. Install the tool dependencies. The app removes filename metadata from $...$ records, then asks Hashcat to identify compatible modes. Only recognized output is saved. If several modes match, select the correct one before importing. The catalog has 78 entries; support depends on the exact format and tool versions. Binary outputs and formats without $...$ records need external preparation. A file's extension alone cannot determine its hash mode. Raw MD5/SHA/NTLM text needs no packet conversion.</p>"
    "<h3>Troubleshooting</h3><p>No devices: inspect devices and install the compute runtime. Token/line-length error: check hash type and whether extraction is needed. Out of memory: reduce workload or select a different device. Unsupported option: read the installed engine's help. GPU temperature depends on the driver exposing telemetry.</p><p><a href='https://hashcat.net/wiki/'>Hashcat wiki</a> · <a href='https://hashcat.net/cap2hashcat/'>Official converter</a> · <a href='https://github.com/ZerBea/hcxtools'>hcxtools</a></p>",
    "<h2>От файла к повторяемой задаче</h2><ol><li>Вверху выберите hashcat.exe (Windows) или hashcat (Linux). Сохраните весь комплект движка, включая modules и OpenCL. Установите вычислительный драйвер производителя GPU; для тестов CPU в Linux подходит PoCL.</li><li>Нажмите <b>Загрузить типы</b>: приложение прочитает справку и типы хешей установленного движка. Номер типа можно ввести вручную.</li><li>Откройте <b>Новую задачу</b>, выберите файл хешей и правильный тип. Формы поддерживают десять режимов Hashcat 8. Отметьте словари и правила, задайте порядок. Профили сохраняют и неотмеченные строки. Режимы 4/5/8/12 требуют Hashcat 8; параметры находятся на расширенных вкладках. В режиме 12 нужен один ?w и, для второго словаря, один ?q после него; наращивание длины недоступно. В режиме ассоциации каждой строке хешей нужна соответствующая строка словаря.</li><li>Добавьте задачу в очередь или запустите сразу. Одновременно выполняется одна задача. Очередь продолжается после успеха или исчерпания кандидатов, но останавливается при ошибке и ручном прерывании.</li><li>Следите за скоростью, числом результатов, устройствами и ожидаемым завершением. Пауза и продолжение подтверждаются статусом движка. Остановка на контрольной точке ждёт сохранения состояния. Обычная остановка даёт процессу восемь секунд, затем завершает зависший процесс принудительно.</li></ol>"
    "<h3>Сессии и результаты</h3><p>У каждой задачи свои restore, potfile и результаты в каталоге данных приложения. Восстановление использует прежние настройки и входные файлы. В Hashcat 8 применяется --restore-position, в старых версиях --restore. Перед восстановлением загрузите справку движка. После запуска приложения прерванные задачи сами не возобновляются. Для изменения задачи скопируйте её в форму и создайте новую. Удаление строки очереди сохраняет её файлы.</p><p>Таблица показывает до 2000 результатов, экспорт сохраняет полный файл хеш:hex. Hex сохраняет любые байты и разделители; отображение UTF-8 может заменять нетекстовые байты. Профили и очередь содержат пути и настройки. Журналы ограничены по объёму и остаются в памяти. Файлы хранятся на вашем компьютере.</p>"
    "<h3>Все команды CLI</h3><p>Вкладка <b>Команды</b> принимает любые аргументы вашей версии: режимы 4/5/8/12, правила, устройства, benchmark, --identify, --show, --left, --keyspace, --stdout, brain и новые опции. Один аргумент на строку, без кавычек оболочки, либо JSON-массив строк. Путь с пробелами — один аргумент. Конвейеры и перенаправления оболочки не выполняются; используйте файловые параметры Hashcat. На интерактивные запросы можно отвечать текстом и Enter. На второй вкладке справки доступен поиск по выводу установленного движка.</p><p>Этот режим запускает ровно заданные аргументы: сессии, файлы результатов и изменяющие входные данные флаги вроде --remove задаёте вы. Параметры управляемой очереди автоматически не добавляются. Кнопка <b>Из формы задачи</b> даёт готовую основу для редактирования.</p>"
    "<h3>Подготовка хешей</h3><p>Онлайн-конвертер Hashcat принимает PCAPNG, PCAP и CAP для WPA/WPA2, режим 22000. Приложение использует тот же hcxpcapngtool локально, добавляет gzip и старые HCCAP/HCCAPX/16800, а также извлечение EAP-MD5 (4800), LEAP/MSCHAPv2 (5500) и TACACS+ (16100). Захват без нужного обмена не даст хешей. В Windows hcxtools запускается внутри WSL, в Linux — напрямую.</p><p>Зашифрованным архивам ZIP/7z/RAR, документам PDF/Office, базам KeePass и дисковым контейнерам тоже нужно извлечение данных. Wi-Fi-конвертер сайта эти форматы НЕ принимает. Откройте вторую вкладку конвертера, выберите установленную утилиту John Jumbo, исходный файл, новый путь результата и, для скрипта, Python или Perl. Установите зависимости утилиты. Приложение удаляет метаданные имени из записей $...$ и проверяет их через Hashcat --identify. Сохраняется только распознанный результат. Если типов несколько, выберите нужный перед импортом. В каталоге 78 записей; поддержка зависит от точного формата и версий. Бинарный вывод и форматы без $...$ требуют отдельной подготовки. Расширение файла само по себе не определяет тип хеша. Текстовые MD5/SHA/NTLM преобразования захватов не требуют.</p>"
    "<h3>Если возникла проблема</h3><p>Нет устройств: проверьте их список и вычислительный драйвер. Ошибка длины строки: проверьте тип хеша и необходимость извлечения. Не хватает памяти: уменьшите нагрузку или смените устройство. Неизвестная опция: откройте справку установленной версии. Температура GPU доступна, только если её предоставляет драйвер.</p><p><a href='https://hashcat.net/wiki/'>Wiki Hashcat</a> · <a href='https://hashcat.net/cap2hashcat/'>Официальный конвертер</a> · <a href='https://github.com/ZerBea/hcxtools'>hcxtools</a></p>"));
  get<QTextBrowser> ("guide")->append (t (
    "<h3>Authors and licenses</h3><p>Combined GUI: GPL-3.0-or-later. Command builder, validators and parser: <a href='https://github.com/rgroesslinger/hashcat-gui'>hashcat-gui, Rainer Groesslinger</a>. Dashboard and extractor catalog: <a href='https://github.com/jjsvs/Hashcat-Reactor'>Hashcat-Reactor, copyright 2025 rabbit, MIT</a>. See THIRD_PARTY.md and the included corresponding source archive. Hashcat remains a separate MIT program.</p>",
    "<h3>Авторы и лицензии</h3><p>Объединённый GUI: GPL-3.0-or-later. Конструктор команд, проверки и парсер: <a href='https://github.com/rgroesslinger/hashcat-gui'>hashcat-gui, Rainer Groesslinger</a>. Панель и каталог конвертеров: <a href='https://github.com/jjsvs/Hashcat-Reactor'>Hashcat-Reactor, copyright 2025 rabbit, MIT</a>. См. THIRD_PARTY.md и архив исходников в комплекте. Hashcat остаётся отдельной программой под MIT.</p>"));
  get<QTextBrowser> ("guide")->moveCursor (QTextCursor::Start);
  refresh_jobs ();
  refresh_form ();
}

Job Window::form_job () const
{
  Job job;
  job.id = "preview";
  job.name = get<QLineEdit> ("jobName")->text ().trimmed ();
  job.binary = QFileInfo (get<QLineEdit> ("binary")->text ()).absoluteFilePath ();
  job.hashes = get<QLineEdit> ("hashFile")->text ();
  job.wordlists = get<PathList> ("wordlists")->checked ();
  job.advanced = get<AdvancedForm> ("advanced")->values ();
  job.editor_state["wordlists"] = get<PathList> ("wordlists")->snapshot ();
  job.editor_state["rules"] = get<PathList> ("rules")->snapshot ();
  job.mask = get<QLineEdit> ("mask")->text ();
  bool ok = false;
  job.hash_mode = get<QComboBox> ("hashMode")->currentText ().section ('|', 0, 0).trimmed ().toInt (&ok);
  if (ok == false) job.hash_mode = -1;
  job.attack = get<QComboBox> ("attack")->currentData ().toInt ();
  job.workload = get<QComboBox> ("workload")->currentData ().toInt ();
  job.device_type = get<QComboBox> ("deviceType")->currentData ().toInt ();
  job.devices = get<QLineEdit> ("devices")->text ().trimmed ();
  job.rules = get<PathList> ("rules")->checked ();
  job.extra = lines (get<QPlainTextEdit> ("extra")->toPlainText ());
  for (int i = 0; i < 4; ++i) job.charsets[i] = get<QLineEdit> (qPrintable ("charset" + QString::number (i + 1)))->text ();
  job.temperature = get<QSpinBox> ("temperature")->value (); job.runtime = get<QSpinBox> ("runtime")->value ();
  job.minimum = get<QSpinBox> ("minimum")->value (); job.maximum = get<QSpinBox> ("maximum")->value ();
  job.increment = get<QCheckBox> ("increment")->isChecked (); job.optimized = get<QCheckBox> ("optimized")->isChecked ();
  job.username = get<QCheckBox> ("username")->isChecked (); job.force = get<QCheckBox> ("force")->isChecked ();
  return job;
}

void Window::set_form (const Job &job)
{
  loading = true;
  get<QLineEdit> ("jobName")->setText (job.name);
  if (job.binary.isEmpty () == false) get<QLineEdit> ("binary")->setText (job.binary);
  get<QLineEdit> ("hashFile")->setText (job.hashes);
  QStringList dictionaries = job.wordlists;
  if (dictionaries.isEmpty ())
  {
    if (!job.dictionary.isEmpty ()) dictionaries << job.dictionary;
    if ((job.attack == 1 || job.attack == 12) && !job.dictionary2.isEmpty ()) dictionaries << job.dictionary2;
  }
  get<PathList> ("wordlists")->restore (job.editor_state["wordlists"].toArray (), dictionaries);
  get<AdvancedForm> ("advanced")->set_values (job.advanced);
  get<QLineEdit> ("mask")->setText (job.mask); get<QLineEdit> ("devices")->setText (job.devices);
  get<QComboBox> ("hashMode")->setEditText (QString::number (job.hash_mode));
  get<QComboBox> ("attack")->setCurrentIndex (get<QComboBox> ("attack")->findData (job.attack));
  get<QComboBox> ("workload")->setCurrentIndex (get<QComboBox> ("workload")->findData (job.workload));
  get<QComboBox> ("deviceType")->setCurrentIndex (get<QComboBox> ("deviceType")->findData (job.device_type));
  get<PathList> ("rules")->restore (job.editor_state["rules"].toArray (), job.rules);
  get<QPlainTextEdit> ("extra")->setPlainText (job.extra.join ('\n'));
  for (int i = 0; i < 4; ++i) get<QLineEdit> (qPrintable ("charset" + QString::number (i + 1)))->setText (job.charsets[i]);
  get<QSpinBox> ("temperature")->setValue (job.temperature); get<QSpinBox> ("runtime")->setValue (job.runtime);
  get<QSpinBox> ("minimum")->setValue (job.minimum); get<QSpinBox> ("maximum")->setValue (job.maximum);
  get<QCheckBox> ("increment")->setChecked (job.increment); get<QCheckBox> ("optimized")->setChecked (job.optimized);
  get<QCheckBox> ("username")->setChecked (job.username); get<QCheckBox> ("force")->setChecked (job.force);
  loading = false;
  refresh_form ();
}

void Window::refresh_form ()
{
  if (loading || (get<QLabel> ("validation") == nullptr)) return;
  const Job job = form_job ();
  const auto attack = static_cast<AttackMode> (job.attack);
  const bool mask = CommandBuilder::attackUsesMask (attack);
  get<PathList> ("wordlists")->setEnabled (CommandBuilder::attackUsesWordlists (attack));
  get<PathList> ("rules")->setEnabled (CommandBuilder::attackUsesRules (attack));
  get<QLineEdit> ("mask")->parentWidget ()->setEnabled (mask);
  get<QCheckBox> ("increment")->parentWidget ()->setEnabled (CommandBuilder::attackUsesIncrement (attack));
  get<AdvancedForm> ("advanced")->set_mode (job.attack);
  get<QPlainTextEdit> ("preview")->setPlainText (display_command (job.binary, job.arguments (root)));
  get<QLabel> ("validation")->setText (job.validate ());
  get<QPushButton> ("addJob")->setEnabled (job.validate ().isEmpty ());
  get<QPushButton> ("startNow")->setEnabled (job.validate ().isEmpty () && (runner.busy () == false) && (probe.state () == QProcess::NotRunning));
}

int Window::selected () const
{
  const int row = get<QTableWidget> ("jobs")->currentRow ();
  return (row >= 0) && (row < jobs.size ()) ? row : -1;
}

void Window::refresh_jobs ()
{
  auto *table = get<QTableWidget> ("jobs");
  const int current = selected ();
  const QSignalBlocker blocker (table);
  table->setRowCount (jobs.size ());
  for (int i = 0; i < jobs.size (); ++i)
  {
    const QStringList values {jobs[i].name, QString::number (jobs[i].hash_mode), QString::number (jobs[i].attack), state_text (jobs[i].state)};
    for (int col = 0; col < values.size (); ++col) table->setItem (i, col, new QTableWidgetItem (values[col]));
  }
  if (current >= 0) table->selectRow (qMin (current, int (jobs.size ()) - 1));
  else if (jobs.isEmpty () == false) table->selectRow (0);
  refresh_controls ();
}

void Window::refresh_controls ()
{
  const bool busy = runner.busy ();
  const bool locked = busy || (probe.state () != QProcess::NotRunning);
  const int index = selected ();
  get<QPushButton> ("runSelected")->setEnabled ((locked == false) && (index >= 0) && (jobs[index].state == "waiting"));
  get<QPushButton> ("restore")->setEnabled ((locked == false) && (index >= 0) && QFileInfo::exists (jobs[index].directory (root) + "/session.restore"));
  get<QPushButton> ("duplicate")->setEnabled (index >= 0);
  get<QPushButton> ("removeJob")->setEnabled ((locked == false) && (index >= 0));
  for (const char *name : {"pause", "resume", "checkpoint", "stop", "expertStop", "sendKeys"}) get<QPushButton> (name)->setEnabled (busy);
  get<QPushButton> ("pause")->setEnabled (busy && (engine_status == 3));
  get<QPushButton> ("resume")->setEnabled (busy && (engine_status == 4));
  get<QPushButton> ("expertRun")->setEnabled (locked == false);
  get<QLineEdit> ("binary")->parentWidget ()->setEnabled (locked == false);
  const bool idle_probe = probe.state () == QProcess::NotRunning;
  for (const char *name : {"loadHelp", "refreshHelp", "probeDevices"}) get<QPushButton> (name)->setEnabled (idle_probe && (busy == false));
  refresh_form ();
}

void Window::add_job (const bool launch)
{
  Job job = form_job ();
  const QString error = job.validate ();
  if (error.isEmpty () == false) { fail (error); return; }
  job.id = QUuid::createUuid ().toString (QUuid::Id128);
  job.hashes = QFileInfo (job.hashes).absoluteFilePath ();
  if (job.dictionary.isEmpty () == false) job.dictionary = QFileInfo (job.dictionary).absoluteFilePath ();
  if (job.dictionary2.isEmpty () == false) job.dictionary2 = QFileInfo (job.dictionary2).absoluteFilePath ();
  for (QString &path : job.wordlists) path = QFileInfo (path).absoluteFilePath ();
  if (QFileInfo (job.mask).isFile ()) job.mask = QFileInfo (job.mask).absoluteFilePath ();
  for (QString &rule : job.rules) rule = QFileInfo (rule).absoluteFilePath ();
  jobs.append (job);
  save (); refresh_jobs ();
  get<QTableWidget> ("jobs")->selectRow (jobs.size () - 1);
  get<QListWidget> ("navigation")->setCurrentRow (0);
  if (launch) start_job (jobs.size () - 1);
}

void Window::start_job (const int index, const bool restore)
{
  if (runner.busy () || (probe.state () != QProcess::NotRunning) || (index < 0) || (index >= jobs.size ())) return;
  Job &job = jobs[index];
  const QString error = job.validate ();
  if (error.isEmpty () == false) { fail (error); return; }
  if (restore && (QFileInfo::exists (job.directory (root) + "/session.restore") == false)) { fail (t ("No restore file.", "Файл восстановления отсутствует.")); return; }
  if (restore && (probe.property ("binary").toString () != job.binary))
  {
    pending_restore = index;
    probe_modes = true;
    probe_output.clear ();
    probe.setProperty ("binary", job.binary);
    probe.setWorkingDirectory (QFileInfo (job.binary).absolutePath ());
    probe.start (job.binary, {"-hh"});
    probe_timer.start (45000);
    refresh_controls ();
    return;
  }
  if ((restore == false) && (job.state != "waiting")) return;
  if (QDir ().mkpath (job.directory (root)) == false) { fail (t ("Cannot create task directory.", "Не удалось создать каталог задачи.")); return; }
  QFile::setPermissions (job.directory (root), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
  QString save_error;
  if (save_json (job.directory (root) + "/job.json", job.json (), &save_error) == false) { fail (save_error); return; }
  active = index; expert = false; stop_requested = false; engine_status = 0; job.state = "running";
  get<QPlainTextEdit> ("log")->clear ();
  get<Telemetry> ("telemetry")->clear ();
  get<QProgressBar> ("progress")->setValue (0);
  for (const char *name : {"speed", "recovered", "eta"}) get<QLabel> (name)->setText ("—");
  append_log (t ("Starting task: ", "Запуск задачи: ") + job.name);
  if (runner.start (job.binary, job.arguments (root, restore, modern_restore), QFileInfo (job.binary).absolutePath ()) == false)
  {
    job.state = "failed"; active = -1;
  }
  save (); refresh_jobs (); refresh_controls ();
}

void Window::start_expert ()
{
  if (runner.busy () || (probe.state () != QProcess::NotRunning)) return;
  const QString binary = get<QLineEdit> ("binary")->text ();
  if (QFileInfo (binary).isExecutable () == false) { fail (t ("Select the Hashcat executable.", "Выберите исполняемый файл Hashcat.")); return; }
  const QString text = get<QPlainTextEdit> ("arguments")->toPlainText ();
  QStringList args;
  if (text.trimmed ().startsWith ('['))
  {
    const auto doc = QJsonDocument::fromJson (text.toUtf8 ());
    if (doc.isArray () == false) { fail (t ("Expected a JSON array of strings.", "Ожидается JSON-массив строк.")); return; }
    for (const auto value : doc.array ())
    {
      if (value.isString () == false) { fail (t ("Every argument must be a string.", "Каждый аргумент должен быть строкой.")); return; }
      args << value.toString ();
    }
  }
  else args = lines (text);
  for (const auto &arg : args)
  {
    if (arg.contains (QChar (0))) { fail (t ("NUL is not a valid command argument.", "Аргумент не может содержать NUL.")); return; }
  }
  QString cwd = get<QLineEdit> ("expertCwd")->text ();
  if (cwd.isEmpty ()) cwd = QFileInfo (binary).absolutePath ();
  if (QFileInfo (cwd).isDir () == false) { fail (t ("Working directory does not exist.", "Рабочий каталог не существует.")); return; }
  expert = true; active = -1; stop_requested = false; engine_status = 0;
  get<QPlainTextEdit> ("consoleOutput")->clear ();
  const QString stdin_file = get<QLineEdit> ("stdinFile")->text ();
  if ((stdin_file.isEmpty () == false) && ((QFileInfo (stdin_file).isFile () == false) || (QFileInfo (stdin_file).isReadable () == false))) { fail (t ("Standard input file is not readable.", "Файл стандартного ввода недоступен.")); return; }
  runner.start (QFileInfo (binary).absoluteFilePath (), args, cwd, stdin_file.isEmpty (), stdin_file);
  refresh_controls ();
}

void Window::run_probe (const QStringList &args, const bool modes)
{
  if ((probe.state () != QProcess::NotRunning) || runner.busy ()) return;
  const QString binary = get<QLineEdit> ("binary")->text ();
  if (QFileInfo (binary).isExecutable () == false) { fail (t ("Select the Hashcat executable.", "Выберите исполняемый файл Hashcat.")); return; }
  probe_modes = modes; probe_output.clear ();
  if (modes) probe.setProperty ("binary", QFileInfo (binary).absoluteFilePath ());
  probe.setWorkingDirectory (QFileInfo (binary).absolutePath ());
  probe.start (QFileInfo (binary).absoluteFilePath (), args);
  probe_timer.start (45000); refresh_controls ();
}

void Window::append_log (const QString &text)
{
  get<QPlainTextEdit> ("log")->appendPlainText (text);
  get<QPlainTextEdit> ("consoleOutput")->appendPlainText (text);
}

void Window::set_status (const QJsonObject &object)
{
  get<Telemetry> ("telemetry")->sample (object);
  engine_status = object["status"].toInt ();
  const QJsonArray progress = object["progress"].toArray ();
  if ((progress.size () == 2) && (progress[1].toDouble () > 0))
    get<QProgressBar> ("progress")->setValue (int (qBound (0.0, progress[0].toDouble () / progress[1].toDouble () * 1000, 1000.0)));
  const QJsonArray recovered = object["recovered_hashes"].toArray ();
  if (recovered.size () == 2) get<QLabel> ("recovered")->setText (QString::number (recovered[0].toInteger ()) + " / " + QString::number (recovered[1].toInteger ()));
  double speed = 0;
  QStringList devices;
  for (const auto &value : object["devices"].toArray ())
  {
    const QJsonObject device = value.toObject ();
    speed += device["speed"].toDouble ();
    QString line = "#" + QString::number (device["device_id"].toInt ()) + " " + device["device_name"].toString () + "  " + speed_text (device["speed"].toDouble ());
    if (device["temp"].toInt (-1) >= 0) line += "  " + QString::number (device["temp"].toInt ()) + " °C";
    if (device["util"].toInt (-1) >= 0) line += "  " + QString::number (device["util"].toInt ()) + "%";
    devices << line;
  }
  get<QLabel> ("speed")->setText (speed_text (speed));
  get<QPlainTextEdit> ("deviceInfo")->setPlainText (devices.join ('\n'));
  const qint64 end = object["estimated_stop"].toInteger ();
  get<QLabel> ("eta")->setText (end > 1 ? QDateTime::fromSecsSinceEpoch (end).toLocalTime ().toString ("MM-dd HH:mm:ss") : "—");
  if ((active >= 0) && (active < jobs.size ()))
  {
    const int status = object["status"].toInt ();
    if (status == 4) jobs[active].state = "paused";
    else if (status == 3) jobs[active].state = "running";
    refresh_jobs ();
  }
  refresh_results ();
  refresh_controls ();
}

void Window::finished (const int code, const bool crashed)
{
  append_log (expert ? t ("Process exit code: ", "Код завершения процесса: ") + QString::number (code) : exit_text (code));
  if ((active >= 0) && (active < jobs.size ()))
  {
    jobs[active].state = stop_requested ? "stopped" : crashed ? "failed" : code == 0 ? "completed" : code == 1 ? "exhausted" : (code >= 2 && code <= 4) ? "stopped" : "failed";
    save ();
  }
  const bool next = (expert == false) && (stop_requested == false) && (crashed == false) && ((code == 0) || (code == 1)) && get<QCheckBox> ("autoNext")->isChecked ();
  active = -1;
  refresh_jobs (); refresh_controls (); refresh_results ();
  if (next)
  {
    QTimer::singleShot (0, this, [this]
    {
      for (int i = 0; i < jobs.size (); ++i)
      {
        if (jobs[i].state == "waiting") { get<QTableWidget> ("jobs")->selectRow (i); start_job (i); return; }
      }
    });
  }
}

void Window::refresh_results ()
{
  auto *table = get<QTableWidget> ("results");
  table->setRowCount (0);
  const int index = selected ();
  if (index < 0) return;
  QFile file (jobs[index].directory (root) + "/results.txt");
  if (file.open (QIODevice::ReadOnly) == false) return;
  int row = 0;
  while ((file.atEnd () == false) && (row < 2000) && (file.pos () < 8 * 1024 * 1024))
  {
    QByteArray line = file.readLine (1024 * 1024).trimmed ();
    const qsizetype separator = line.lastIndexOf (':');
    if (separator < 0) continue;
    const QByteArray hex = line.mid (separator + 1);
    if ((hex.size () % 2 != 0) || (QRegularExpression ("^[0-9a-fA-F]*$").match (QString::fromLatin1 (hex)).hasMatch () == false)) continue;
    table->insertRow (row);
    table->setItem (row, 0, new QTableWidgetItem (QString::fromUtf8 (line.left (separator))));
    table->setItem (row, 1, new QTableWidgetItem (QString::fromUtf8 (QByteArray::fromHex (hex))));
    ++row;
  }
}

void Window::fail (const QString &text)
{
  append_log (text);
  statusBar ()->showMessage (text, 15000);
  QMessageBox::warning (this, "Hashcat Desktop", text);
}

void Window::save ()
{
  if (loading) return;
  QJsonArray list;
  for (const Job &job : jobs) list.append (job.json ());
  const QJsonObject document {{"version", 1}, {"jobs", list}, {"language", qApp->property ("language").toString ()},
    {"binary", get<QLineEdit> ("binary")->text ()}, {"hcx", get<QLineEdit> ("hcxDirectory")->text ()}, {"wsl", get<QCheckBox> ("useWsl")->isChecked ()},
    {"john", get<QLineEdit> ("johnDirectory")->text ()}, {"interpreter", get<QLineEdit> ("extractInterpreter")->text ()}};
  QString error;
  if (save_json (QDir (root).filePath ("workspace.json"), document, &error) == false) statusBar ()->showMessage (error, 15000);
}

void Window::load ()
{
  loading = true;
  QFile file (QDir (root).filePath ("workspace.json"));
  QJsonObject obj;
  if (file.open (QIODevice::ReadOnly) && (file.size () <= 16 * 1024 * 1024)) obj = QJsonDocument::fromJson (file.readAll ()).object ();
  qApp->setProperty ("language", obj["language"].toString ("ru"));
  const QSignalBlocker blocker (get<QComboBox> ("language"));
  get<QComboBox> ("language")->setCurrentIndex (russian () ? 0 : 1);
  QString binary = obj["binary"].toString ();
  if (binary.isEmpty ())
  {
    binary = QStandardPaths::findExecutable ("hashcat");
    for (const QString &relative : {QString ("hashcat.exe"), QString ("hashcat/hashcat.exe"), QString ("../hashcat"), QString ("hashcat")})
    {
      const QFileInfo candidate (QDir (QApplication::applicationDirPath ()).filePath (relative));
      if (candidate.isFile () && candidate.isExecutable ()) { binary = candidate.absoluteFilePath (); break; }
    }
  }
  get<QLineEdit> ("binary")->setText (binary);
  get<QLineEdit> ("jobName")->setText (t ("My task", "Моя задача"));
  get<QLineEdit> ("hcxDirectory")->setText (obj["hcx"].toString ());
  get<QLineEdit> ("johnDirectory")->setText (obj["john"].toString ());
  get<QLineEdit> ("extractInterpreter")->setText (obj["interpreter"].toString ());
#ifdef Q_OS_WIN
  get<QCheckBox> ("useWsl")->setChecked (obj["wsl"].toBool (true));
#endif
  QSet<QString> ids;
  for (const auto &value : obj["jobs"].toArray ())
  {
    Job job = Job::from_json (value.toObject ());
    if ((QRegularExpression ("^[a-zA-Z0-9_-]{1,64}$").match (job.id).hasMatch () == false) || ids.contains (job.id)) continue;
    ids.insert (job.id);
    if ((job.state == "running") || (job.state == "paused")) job.state = "interrupted";
    jobs.append (job);
  }
  loading = false;
}

void Window::closeEvent (QCloseEvent *event)
{
  if (runner.busy () || converter.busy () || extractor.busy ())
  {
    const auto answer = QMessageBox::question (this, "Hashcat Desktop", t ("A process is running. Stop it and close? Use a checkpoint stop first if you need a fresh restore point.", "Процесс выполняется. Остановить его и закрыть? Если нужна свежая точка восстановления, сначала остановите на контрольной точке."));
    if (answer != QMessageBox::Yes) { event->ignore (); return; }
    stop_requested = true;
    if (active >= 0) jobs[active].state = "interrupted";
    runner.kill (); converter.cancel (); extractor.cancel ();
  }
  if (probe.state () != QProcess::NotRunning) { probe.kill (); probe.waitForFinished (3000); }
  save ();
  event->accept ();
}
