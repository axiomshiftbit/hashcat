/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#pragma once

#include <QJsonObject>
#include <QStringList>
#include "hashcatoptions.h"

struct Job
{
  QString id, name, binary, hashes, dictionary, dictionary2, mask, devices;
  QStringList rules, extra;
  QStringList wordlists;
  QJsonObject advanced, editor_state;
  QString charsets[4];
  int hash_mode = 0, attack = 0, workload = 2, device_type = 0;
  int temperature = 85, runtime = 0, minimum = 1, maximum = 8;
  bool increment = false, optimized = false, username = false, force = false;
  QString state = "waiting";
  QString directory (const QString &root) const;
  QString validate () const;
  HashcatOptions command_options () const;
  QStringList arguments (const QString &root, bool restore = false, bool modern = true) const;
  QJsonObject json () const;
  static Job from_json (const QJsonObject &object);
};

bool save_json (const QString &path, const QJsonObject &object, QString *error);
QString display_command (const QString &binary, const QStringList &arguments);
QString state_text (const QString &state);
QString exit_text (int code);
QString speed_text (double speed);
QList<QPair<int, QString>> parse_modes (const QByteArray &help);
