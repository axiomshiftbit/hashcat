/* SPDX-License-Identifier: GPL-3.0-or-later
 * List operations adapted from rgroesslinger/hashcat-gui, Rainer Groesslinger.
 */
#pragma once
#include <QWidget>
#include <QJsonArray>
#include <QStringList>
class QListWidget;

class PathList : public QWidget
{
  Q_OBJECT
public:
  explicit PathList (bool folders, QWidget *parent = nullptr);
  QStringList checked () const;
  QJsonArray snapshot () const;
  void restore (const QJsonArray &state, const QStringList &fallback = {});
  void add_paths (const QStringList &paths);
  void move_selected (int delta);
  void retranslate ();
signals:
  void changed ();
private:
  QListWidget *list;
};
