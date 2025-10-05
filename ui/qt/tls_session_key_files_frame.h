/** @file
 *
 * Copyright 2019 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TLS_SESSION_KEY_FILES_FRAME_H
#define TLS_SESSION_KEY_FILES_FRAME_H

#include <config.h>

#include <QFrame>

#include <ui/qt/models/uat_model.h>

namespace Ui {
class TlsSessionKeyFilesFrame;
}

class TlsSessionKeyFilesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit TlsSessionKeyFilesFrame(QWidget *parent = NULL);
    ~TlsSessionKeyFilesFrame();

    void acceptChanges();
    void rejectChanges();

private:
    Ui::TlsSessionKeyFilesFrame *ui;

    UatModel *tls_session_key_files_model_;

    void addKey(const QString &filename);

private slots:
    void keyCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
    void on_addSessionKeyFileButton_clicked();
    void on_deleteSessionKeyFileButton_clicked();
};

#endif  /* TLS_SESSION_KEY_FILES_FRAME_H */
