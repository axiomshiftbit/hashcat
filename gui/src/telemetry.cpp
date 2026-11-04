// SPDX-License-Identifier: GPL-3.0-or-later
// Dashboard layout/palette adapted from Hashcat-Reactor (c) 2025 rabbit, MIT.
// See third_party/hashcat_reactor/LICENSE. All data comes from Hashcat status.
#include "telemetry.h"
#include "job.h"
#include "lang.h"
#include <QPainter>
#include <QPainterPath>
#include <QDateTime>
#include <QMouseEvent>
#include <QToolTip>
#include <cmath>

Telemetry::Telemetry (QWidget *parent) : QWidget (parent)
{
  setMinimumHeight (205); setMouseTracking (true);
}

void Telemetry::clear () { history.clear (); devices = {}; setMinimumHeight (205); update (); }

void Telemetry::sample (const QJsonObject &status)
{
  devices = status["devices"].toArray ();
  double total = 0;
  for (const auto &value : devices) total += value.toObject ()["speed"].toDouble ();
  if (!std::isfinite (total) || total < 0) return;
  history.append ({double (QDateTime::currentMSecsSinceEpoch ()), total});
  while (history.size () > 60) history.removeFirst ();
  setMinimumHeight (qMax (205, int (devices.size ()) * 78 + 30)); update ();
}

QRectF Telemetry::chart_rect () const { return {95, 42, width () * 0.64 - 115, height () - 76.0}; }

void Telemetry::paintEvent (QPaintEvent *)
{
  QPainter p (this); p.setRenderHint (QPainter::Antialiasing);
  const QRectF plot = chart_rect ();
  p.setPen (QColor ("#283044")); p.setBrush (QColor ("#0b1122"));
  p.drawRoundedRect (QRectF (1, 1, width () * .64 - 4, height () - 2), 10, 10);
  p.setPen (QColor ("#a5b4fc"));
  p.drawText (QRectF (18, 10, width () * .6, 25), t ("HASHRATE · last 60 samples", "СКОРОСТЬ · последние 60 измерений"));
  double max = 1;
  for (const auto &point : history) max = qMax (max, point.y ());
  for (int i = 0; i <= 3; ++i)
  {
    const double y = plot.bottom () - plot.height () * i / 3;
    p.setPen (QPen (QColor ("#283044"), 1, Qt::DashLine)); p.drawLine (QPointF (plot.left (), y), QPointF (plot.right (), y));
    p.setPen (QColor ("#8492aa"));
    p.drawText (QRectF (5, y - 10, 83, 25), Qt::AlignRight | Qt::AlignVCenter, speed_text (max * i / 3));
  }
  if (history.size () > 1)
  {
    const double span = qMax (1.0, history.last ().x () - history.first ().x ());
    QPainterPath line;
    for (int i = 0; i < history.size (); ++i)
    {
      const QPointF point (plot.left () + (history[i].x () - history.first ().x ()) / span * plot.width (), plot.bottom () - history[i].y () / max * plot.height ());
      if (i == 0) line.moveTo (point); else line.lineTo (point);
    }
    auto area = line; area.lineTo (plot.bottomRight ()); area.lineTo (plot.bottomLeft ()); area.closeSubpath ();
    QLinearGradient fill (plot.topLeft (), plot.bottomLeft ()); fill.setColorAt (0, QColor (99, 102, 241, 110)); fill.setColorAt (1, QColor (99, 102, 241, 0));
    p.fillPath (area, fill); p.setPen (QPen (QColor ("#818cf8"), 2)); p.drawPath (line);
    p.setPen (QColor ("#8492aa"));
    p.drawText (QRectF (plot.left (), plot.bottom () + 5, plot.width (), 24), QDateTime::fromMSecsSinceEpoch (qint64 (history.last ().x ())).toString ("HH:mm:ss"));
  }
  else
  {
    p.setPen (QColor ("#8492aa")); p.drawText (plot, Qt::AlignCenter, t ("Waiting for engine samples", "Ожидание данных движка"));
  }
  const double x = width () * .64 + 10, w = width () - x - 2;
  p.setPen (QColor ("#a5b4fc")); p.drawText (QRectF (x, 2, w, 25), t ("COMPUTE DEVICES", "ВЫЧИСЛИТЕЛЬНЫЕ УСТРОЙСТВА"));
  if (devices.isEmpty ())
  {
    p.setPen (QColor ("#8492aa")); p.drawText (QRectF (x, 35, w, 90), Qt::TextWordWrap, t ("Device readings appear when a task starts. Missing sensors are shown as —.", "Показатели устройств появятся после запуска задачи. Недоступные датчики обозначены —."));
  }
  for (int i = 0; i < devices.size (); ++i)
  {
    const auto device = devices[i].toObject (); const double y = 30 + i * 78;
    p.setPen (QColor ("#283044")); p.setBrush (QColor ("#111a2c")); p.drawRoundedRect (QRectF (x, y, w, 70), 8, 8);
    p.setPen (QColor ("#e2e8f0"));
    const QString name = "#" + QString::number (device["device_id"].toInt ()) + " " + device["device_name"].toString ();
    p.drawText (QRectF (x + 10, y + 5, w - 20, 23), fontMetrics ().elidedText (name, Qt::ElideRight, int (w - 20)));
    const int temp = device["temp"].toInt (-1), util = device["util"].toInt (-1);
    p.setPen (QColor (temp >= 80 ? "#f87171" : temp >= 60 ? "#facc15" : "#6ee7b7"));
    p.drawText (QRectF (x + 10, y + 32, w - 20, 28), speed_text (device["speed"].toDouble ()) + "  ·  " + (temp >= 0 ? QString::number (temp) + " °C" : "— °C") + "  ·  " + (util >= 0 ? QString::number (util) + "%" : "— %"));
  }
}

void Telemetry::mouseMoveEvent (QMouseEvent *event)
{
  const QRectF plot = chart_rect ();
  if (history.isEmpty () || !plot.contains (event->position ())) return;
  const double target = history.first ().x () + (event->position ().x () - plot.left ()) / plot.width () * (history.last ().x () - history.first ().x ());
  QPointF nearest = history.first ();
  for (const auto &point : history) if (std::abs (point.x () - target) < std::abs (nearest.x () - target)) nearest = point;
  QToolTip::showText (event->globalPosition ().toPoint (), QDateTime::fromMSecsSinceEpoch (qint64 (nearest.x ())).toString ("HH:mm:ss") + "  " + speed_text (nearest.y ()), this);
}
