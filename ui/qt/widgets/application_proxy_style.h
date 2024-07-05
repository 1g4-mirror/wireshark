/* application_proxy_style.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef APPLICATION_PROXY_STYLE_H_
#define APPLICATION_PROXY_STYLE_H_

#include <QProxyStyle>

class ApplicationProxyStyle : public QProxyStyle
{
public:
    void drawPrimitive(QStyle::PrimitiveElement element, const QStyleOption *option, QPainter *p, const QWidget *widget = nullptr) const;
    QRect subElementRect(SubElement sr, const QStyleOption *opt, const QWidget *widget) const;
};

#endif /* APPLICATION_PROXY_STYLE_H_ */
