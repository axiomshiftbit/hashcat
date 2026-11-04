/* SPDX-License-Identifier: GPL-3.0-or-later
 * List operations adapted from rgroesslinger/hashcat-gui, Rainer Groesslinger.
 * See third_party/hashcat_gui/UPSTREAM.json and LICENSE.
 */
#include "pathlist.h"
#include "lang.h"
#include <QListWidget>
#include <QPushButton>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QJsonObject>
#include <QDir>
#include <QSignalBlocker>

PathList::PathList (const bool folders, QWidget *parent) : QWidget (parent)
{
  auto *layout = new QVBoxLayout (this); layout->setContentsMargins (0, 0, 0, 0);
  list = new QListWidget; list->setObjectName ("entries");
  list->setSelectionMode (QAbstractItemView::ExtendedSelection);
  list->setMinimumHeight (85); list->setMaximumHeight (130);
  layout->addWidget (list);
  auto *actions = new QHBoxLayout; layout->addLayout (actions);
  const QStringList ids {"files", "folder", "remove", "up", "down"};
  for (const QString &id : ids)
  {
    auto *b = new QPushButton; b->setObjectName (id); actions->addWidget (b);
    if (id == "folder") b->setVisible (folders);
    connect (b, &QPushButton::clicked, this, [this, id]
    {
      if (id == "files") add_paths (QFileDialog::getOpenFileNames (this, t ("Add files", "Добавить файлы")));
      else if (id == "folder") add_paths ({QFileDialog::getExistingDirectory (this, t ("Add folder", "Добавить каталог"))});
      else if (id == "up" || id == "down") move_selected (id == "up" ? -1 : 1);
      else
      {
        for (QListWidgetItem *item : list->selectedItems ()) delete item;
        list->clearSelection (); emit changed ();
      }
    });
  }
  connect (list, &QListWidget::itemChanged, this, &PathList::changed);
  retranslate ();
}

void PathList::retranslate ()
{
  const QStringList ids {"files", "folder", "remove", "up", "down"};
  const QStringList texts {t ("Files", "Файлы"), t ("Folder", "Каталог"), t ("Remove", "Убрать"), "↑", "↓"};
  for (int i = 0; i < ids.size (); ++i) findChild<QPushButton *> (ids[i])->setText (texts[i]);
}

void PathList::add_paths (const QStringList &paths)
{
  const QSignalBlocker blocker (list);
  for (const QString &path : paths)
  {
    const QString native = QDir::toNativeSeparators (path);
    if (native.isEmpty () || !list->findItems (native, Qt::MatchExactly).isEmpty ()) continue;
    auto *item = new QListWidgetItem (native, list);
    item->setCheckState (Qt::Checked); item->setToolTip (native);
  }
  emit changed ();
}

QStringList PathList::checked () const
{
  QStringList paths;
  for (int i = 0; i < list->count (); ++i)
    if (list->item (i)->checkState () == Qt::Checked) paths << list->item (i)->text ();
  return paths;
}

void PathList::move_selected (const int delta)
{
  const int current = list->currentRow (), target = current + delta;
  if (current < 0 || target < 0 || target >= list->count ()) return;
  auto *item = list->takeItem (current); list->insertItem (target, item); list->setCurrentRow (target);
  emit changed ();
}

QJsonArray PathList::snapshot () const
{
  QJsonArray result;
  for (int i = 0; i < list->count (); ++i)
    result.append (QJsonObject {{"path", list->item (i)->text ()}, {"enabled", list->item (i)->checkState () == Qt::Checked}});
  return result;
}

void PathList::restore (const QJsonArray &state, const QStringList &fallback)
{
  const QSignalBlocker blocker (list);
  list->clear ();
  if (state.isEmpty ()) add_paths (fallback);
  else for (const auto &value : state)
  {
    const auto object = value.toObject ();
    const QString path = object["path"].toString ();
    if (path.isEmpty ()) continue;
    auto *item = new QListWidgetItem (path, list);
    item->setCheckState (object["enabled"].toBool (true) ? Qt::Checked : Qt::Unchecked);
    item->setToolTip (path);
  }
  emit changed ();
}
