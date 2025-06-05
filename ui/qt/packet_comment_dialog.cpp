/* packet_comment_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_comment_dialog.h"
#include <ui_packet_comment_dialog.h>
#include <QKeyEvent>

#include "main_application.h"

PacketCommentDialog::PacketCommentDialog(bool isEdit, QWidget *parent, QString comment) :
    GeometryStateDialog(parent),
    pc_ui_(new Ui::PacketCommentDialog)
{

    QString title = isEdit
        ? tr("Edit Packet Comment")
        : tr("Add Packet Comment");

    pc_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(mainApp->windowTitleString(title));

    pc_ui_->commentTextEdit->setPlainText(comment);
}

PacketCommentDialog::~PacketCommentDialog()
{
    delete pc_ui_;
}

QString PacketCommentDialog::text()
{
    return pc_ui_->commentTextEdit->toPlainText();
}

void PacketCommentDialog::on_buttonBox_helpRequested()
{
//    mainApp->helpTopicAction(HELP_PACKET_COMMENT_DIALOG);
}

void PacketCommentDialog::keyPressEvent(QKeyEvent *event)
{
#ifdef Q_OS_MAC
    bool modifier = event->modifiers() & Qt::MetaModifier; // Command key
#else
    bool modifier = event->modifiers() & Qt::ControlModifier;
#endif

    if (modifier && (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter)) {
        accept(); // Same as pressing OK
        return;
    }

    GeometryStateDialog::keyPressEvent(event); // Pass to base class
}
