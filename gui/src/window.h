/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#pragma once

#include "job.h"
#include "runner.h"
#include "converter.h"

#include <QMainWindow>
#include <QProcess>
#include <QTimer>

class QFormLayout;
class QLineEdit;
class QVBoxLayout;
class QComboBox;

class Window : public QMainWindow
{
  Q_OBJECT
public:
  explicit Window (const QString &data_directory, QWidget *parent = nullptr);
  Job form_job () const;
  void set_form (const Job &job);
  Runner *engine () { return &runner; }
  QString data_directory () const { return root; }
protected:
  void closeEvent (QCloseEvent *event) override;
private:
  template<class T> T *get (const char *name) const { return findChild<T *> (QString::fromLatin1 (name)); }
  void build ();
  QWidget *dashboard ();
  QWidget *editor ();
  QWidget *console_page ();
  QWidget *converter_page ();
  QWidget *help_page ();
  QWidget *path_field (const char *name, bool directory = false, bool save = false);
  void retranslate ();
  void refresh_form ();
  void refresh_jobs ();
  void refresh_controls ();
  void refresh_results ();
  void add_job (bool launch);
  void start_job (int index, bool restore = false);
  void start_expert ();
  void run_probe (const QStringList &args, bool modes = false);
  void save ();
  void load ();
  void append_log (const QString &text);
  void fail (const QString &text);
  void set_status (const QJsonObject &object);
  void finished (int code, bool crashed);
  int selected () const;
  QString root;
  QList<Job> jobs;
  Runner runner;
  Converter converter;
  QProcess probe;
  QTimer probe_timer;
  QByteArray probe_output;
  QString help_text;
  bool probe_modes = false, modern_restore = false, stop_requested = false, expert = false, loading = false;
  int active = -1;
  int pending_restore = -1;
  int engine_status = 0;
};
