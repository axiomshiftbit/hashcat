/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
#pragma once
#include <QCoreApplication>
#include <QVariant>

inline bool russian ()
{
  return qApp->property ("language").toString () != "en";
}

inline QString t (const char *en, const char *ru)
{
  return QString::fromUtf8 (russian () ? ru : en);
}
