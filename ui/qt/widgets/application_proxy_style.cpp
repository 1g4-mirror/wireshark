/* application_proxy_style.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/application_proxy_style.h>
#include <ui/qt/utils/color_utils.h>

#include <QColor>
#include <QPainter>
#include <QStyle>
#include <QStyleOption>
#include <QWidget>

/*
 * Application-wide override of Qt widget styles.
 */

void ApplicationProxyStyle::drawPrimitive(QStyle::PrimitiveElement element, const QStyleOption *option, QPainter *p, const QWidget *widget) const
{
    if (element == QStyle::PE_IndicatorBranch) {
        /* Customize PE_IndicatorBranch appearance to suit row size. */
        const bool children = option->state & QStyle::State_Children;

        if (children) {
            const bool open = option->state & QStyle::State_Open;
            const bool selected = option->state & QStyle::State_Selected;
            float size = std::min(option->rect.width(), option->rect.height());
            const float smallCellFraction = 2.2f;
            const float largeCellFraction = 5.0f;
            const float sensibleSize = 3.0f;
            QPolygon arrow;
            QColor color;

            /* Draw a disclosure widget. */
            if (size < sensibleSize * smallCellFraction)
                size /= smallCellFraction; /* Small cell: The arrow should occupy most of the space. */
            else if (size < sensibleSize * largeCellFraction)
                size = sensibleSize;
            else
                size /= largeCellFraction; /* Large cell: The arrow should occupy a smaller proportion of the space. */

            if (open)
                /* v */
                arrow << QPoint(-size, 0.0f) << QPoint(0.0f, size) << QPoint(size, 0.0f);
            else
                /* > */
                arrow << QPoint(0.0f, size) << QPoint(size, 0.0f) << QPoint(0.0f, -size);

            arrow.translate(QRect(option->rect).center() - arrow.boundingRect().center());

            if (selected)
                color = option->palette.highlightedText().color();
            else {
                color = option->palette.windowText().color();
                if (!open)
                    /* Less emphasis for closed branches. */
                    color = ColorUtils::alphaBlend(color, option->palette.base().color(), 0.35f);
            }
            p->setRenderHints(QPainter::Antialiasing);
            p->setPen(QPen(color, 0.5f + size / 3.0f, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
            p->drawPolyline(arrow);
        }
    } else
        QProxyStyle::drawPrimitive(element, option, p, widget);
}

QRect ApplicationProxyStyle::subElementRect(SubElement sr, const QStyleOption *opt, const QWidget *widget) const
{
    if (sr == SE_TreeViewDisclosureItem)
        /* Bypass any platform-specific style adjustments to the sub-element bounds. */
        return opt->rect;
    return QProxyStyle::subElementRect(sr, opt, widget);
}
