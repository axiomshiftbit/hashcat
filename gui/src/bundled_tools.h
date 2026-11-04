// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QProcessEnvironment>
#include <QString>

QString bundled_tool (const QString &relative);
QString bundled_interpreter (const QString &suffix, const QString &tool = {});
QProcessEnvironment tool_environment (const QString &program);
QString tool_input_path (const QString &program, const QString &path);
