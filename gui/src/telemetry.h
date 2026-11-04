// SPDX-License-Identifier: GPL-3.0-or-later
// Native adaptation of Hashcat-Reactor's dashboard and device cards (MIT).
#pragma once
#include <QWidget>
#include <QJsonArray>
#include <QPointF>
class Telemetry : public QWidget
{
  Q_OBJECT
public:
  explicit Telemetry (QWidget *parent = nullptr);
  void sample (const QJsonObject &status);
  void clear ();
  int sample_count () const { return history.size (); }
protected:
  void paintEvent (QPaintEvent *) override;
  void mouseMoveEvent (QMouseEvent *event) override;
private:
  QList<QPointF> history;
  QJsonArray devices;
  QRectF chart_rect () const;
};
