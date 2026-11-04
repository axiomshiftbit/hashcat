// SPDX-License-Identifier: GPL-3.0-or-later
#include "advancedform.h"
#include "lang.h"
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QCheckBox>
#include <QSpinBox>
#include <QJsonArray>

namespace
{
struct Field { const char *key, *en, *ru; char type; int tab; };
const Field fields[] {
  {"ruleLeft", "Left rule (-j)", "Правило слева (-j)", 's', 0},
  {"ruleRight", "Right rule (-k)", "Правило справа (-k)", 's', 0},
  {"generateRules", "Generate rules (-g)", "Генерировать правила (-g)", 'n', 0},
  {"rulesConcat", "Concatenate rules", "Объединять правила", 'b', 0},
  {"hexWordlist", "Hex wordlist", "Словарь в hex", 'b', 0},
  {"hexCharset", "Hex character sets", "Наборы символов в hex", 'b', 0},
  {"hexSalt", "Hex salt", "Соль в hex", 'b', 0},
  {"encodingFrom", "Source encoding", "Исходная кодировка", 's', 0},
  {"encodingTo", "Target encoding", "Целевая кодировка", 's', 0},
  {"hashRecipe", "Hash recipe (mode 4000)", "Рецепт хеша (тип 4000)", 's', 0},
  {"skip", "Skip candidates", "Пропустить кандидатов", 's', 0},
  {"limit", "Limit candidates", "Ограничить кандидатов", 's', 0},
  {"cpuAffinity", "CPU affinity", "Привязка к ядрам CPU", 's', 0},
  {"cachePath", "Cache directory", "Каталог кеша", 's', 0},
  {"pcfgRulesets", "Rulesets: one path/name per line; empty = default", "Наборы PCFG: путь/имя на строку; пусто = стандартный", 'l', 1},
  {"pcfgScale", "scale", "scale", 's', 1}, {"pcfgCostmax", "costmax", "costmax", 's', 1},
  {"pcfgWeights", "weights", "weights", 's', 1}, {"pcfgThreads", "threads", "threads", 's', 1},
  {"pcfgKbits", "kbits", "kbits", 's', 1}, {"pcfgMaxword", "maxword", "maxword", 's', 1},
  {"pcfgMaxgain", "maxgain", "maxgain", 's', 1}, {"pcfgWalk", "walk", "walk", 's', 1},
  {"pcfgMask", "mask", "mask", 's', 1},
  {"pcfgExtraSettings", "Extra key=value, one per line", "Дополнительно: ключ=значение на строку", 'l', 1},
  {"tableFiles", "Table files: one path per line", "Таблицы: путь на строку", 'l', 2},
  {"tableIdentity", "identity", "identity", 's', 2}, {"tableTemplate", "template", "template", 's', 2},
  {"tableSingle", "single", "single", 's', 2}, {"tableCap", "cap", "cap", 's', 2},
  {"tableMaxperm", "maxperm", "maxperm", 's', 2},
  {"tableExtraSettings", "Extra key=value, one per line", "Дополнительно: ключ=значение на строку", 'l', 2},
  {"feedName", "Feed name or library path", "Имя генератора или путь библиотеки", 's', 3},
  {"feedArguments", "Feed arguments: one argument per line", "Аргументы генератора: один на строку", 'l', 3},
  {"associationSettings", "Association key=value (without dictionaries)", "Ассоциация: ключ=значение (без словарей)", 'l', 4}
};
}

AdvancedForm::AdvancedForm (QWidget *parent) : QTabWidget (parent)
{
  QFormLayout *forms[5];
  for (int i = 0; i < 5; ++i)
  {
    auto *page = new QWidget; forms[i] = new QFormLayout (page);
    forms[i]->setFieldGrowthPolicy (QFormLayout::AllNonFixedFieldsGrow);
    addTab (page, "");
  }
  for (const Field &field : fields)
  {
    QWidget *input;
    if (field.type == 'l')
    {
      auto *text = new QPlainTextEdit; text->setMaximumHeight (75); input = text;
      connect (text, &QPlainTextEdit::textChanged, this, &AdvancedForm::changed);
    }
    else if (field.type == 'b')
    {
      auto *box = new QCheckBox; input = box; connect (box, &QCheckBox::toggled, this, &AdvancedForm::changed);
    }
    else if (field.type == 'n')
    {
      auto *spin = new QSpinBox; spin->setRange (0, 2147483647); input = spin;
      connect (spin, &QSpinBox::valueChanged, this, &AdvancedForm::changed);
    }
    else
    {
      auto *text = new QLineEdit; input = text; connect (text, &QLineEdit::textChanged, this, &AdvancedForm::changed);
    }
    input->setObjectName (field.key);
    auto *label = new QLabel; label->setObjectName (QString (field.key) + "Label"); label->setWordWrap (true);
    forms[field.tab]->addRow (label, input);
  }
  retranslate ();
}

void AdvancedForm::retranslate ()
{
  setTabText (0, t ("Options", "Параметры")); setTabText (1, "4 · PCFG");
  setTabText (2, t ("5 · Table", "5 · Таблица")); setTabText (3, t ("8 · Feed", "8 · Генератор"));
  setTabText (4, t ("9 · Association", "9 · Ассоциация"));
  for (const Field &field : fields) findChild<QLabel *> (QString (field.key) + "Label")->setText (t (field.en, field.ru));
}

void AdvancedForm::set_mode (const int attack)
{
  const int modes[] {0, 4, 5, 8, 9};
  for (int i = 1; i < 5; ++i) setTabEnabled (i, attack == modes[i]);
  if (!isTabEnabled (currentIndex ())) setCurrentIndex (0);
}

QJsonObject AdvancedForm::values () const
{
  QJsonObject result;
  for (const Field &field : fields)
  {
    if (field.type == 'l')
    {
      QJsonArray items;
      for (const QString &line : findChild<QPlainTextEdit *> (field.key)->toPlainText ().split ('\n'))
        if (!line.isEmpty ()) items.append (line);
      result[field.key] = items;
    }
    else if (field.type == 'b') result[field.key] = findChild<QCheckBox *> (field.key)->isChecked ();
    else if (field.type == 'n') result[field.key] = findChild<QSpinBox *> (field.key)->value ();
    else result[field.key] = findChild<QLineEdit *> (field.key)->text ();
  }
  return result;
}

void AdvancedForm::set_values (const QJsonObject &values)
{
  for (const Field &field : fields)
  {
    const QJsonValue value = values[field.key];
    if (field.type == 'l')
    {
      QStringList lines; for (const auto &item : value.toArray ()) lines << item.toString ();
      findChild<QPlainTextEdit *> (field.key)->setPlainText (lines.join ('\n'));
    }
    else if (field.type == 'b') findChild<QCheckBox *> (field.key)->setChecked (value.toBool ());
    else if (field.type == 'n') findChild<QSpinBox *> (field.key)->setValue (value.toInt ());
    else findChild<QLineEdit *> (field.key)->setText (value.toString ());
  }
}
