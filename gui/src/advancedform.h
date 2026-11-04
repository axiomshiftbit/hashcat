// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QTabWidget>
#include <QJsonObject>
class AdvancedForm : public QTabWidget
{
  Q_OBJECT
public:
  explicit AdvancedForm (QWidget *parent = nullptr);
  QJsonObject values () const;
  void set_values (const QJsonObject &values);
  void set_mode (int attack);
  void retranslate ();
signals:
  void changed ();
};
