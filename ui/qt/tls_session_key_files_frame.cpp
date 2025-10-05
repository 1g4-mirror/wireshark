/* tls_session_key_files_frame.cpp
 *
 * Copyright 2025 Edwin Groothuis <wireshark@mavetju.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "main_application.h"
#include "tls_session_key_files_frame.h"
#include <ui_tls_session_key_files_frame.h>

#include "ui/qt/widgets/wireshark_file_dialog.h"
#include <wsutil/report_message.h>
#include <QMessageBox>
#include <ui/all_files_wildcard.h>

#include <epan/secrets.h>
#include <QInputDialog>

#include <epan/dissectors/packet-tls-utils.h>

TlsSessionKeyFilesFrame::TlsSessionKeyFilesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::TlsSessionKeyFilesFrame),
    tls_session_key_files_model_(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->addSessionKeyFileButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteSessionKeyFileButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    tls_session_key_files_model_ = new UatModel(this, "TLS Session Key Files");
    ui->sessionKeyFilesView->setModel(tls_session_key_files_model_);
    connect(ui->sessionKeyFilesView->selectionModel(), &QItemSelectionModel::currentChanged,
           this, &TlsSessionKeyFilesFrame::keyCurrentChanged);
}

TlsSessionKeyFilesFrame::~TlsSessionKeyFilesFrame()
{
    delete ui;
}

void TlsSessionKeyFilesFrame::addKey(const QString &filename)
{
    // Create a new UAT entry with the given filename
    int row = tls_session_key_files_model_->rowCount();
    tls_session_key_files_model_->insertRows(row, 1);
    tls_session_key_files_model_->setData(tls_session_key_files_model_->index(row, 0), filename);
    ui->sessionKeyFilesView->setCurrentIndex(tls_session_key_files_model_->index(row, 0));
}

void TlsSessionKeyFilesFrame::keyCurrentChanged(const QModelIndex &current, const QModelIndex & /* previous */)
{
    ui->deleteSessionKeyFileButton->setEnabled(current.isValid());
}

void TlsSessionKeyFilesFrame::on_addSessionKeyFileButton_clicked()
{
    QString filter =
        tr("TLS Session Key files (*.keys);;All Files (" ALL_FILES_WILDCARD ")");
    QString filename = WiresharkFileDialog::getOpenFileName(this,
            tr("Select TLS Session Key file"), "", filter);

    // XXX do something with the file added

    addKey(filename);
}

void TlsSessionKeyFilesFrame::on_deleteSessionKeyFileButton_clicked()
{
    const QModelIndex &current = ui->sessionKeyFilesView->currentIndex();
    if (tls_session_key_files_model_ && current.isValid()) {
        tls_session_key_files_model_->removeRows(current.row(), 1);
    }
}

void TlsSessionKeyFilesFrame::acceptChanges()
{
    QString error;
    if (tls_session_key_files_model_->applyChanges(error) && !error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    }

    // For some reason UAT_AFFECTS_DISSECTION on uat_tls_session_key_files
    // doesn't work. So we poke the main application from here.
    mainApp->queueAppSignal(MainApplication::PacketDissectionChanged);
}

void TlsSessionKeyFilesFrame::rejectChanges()
{
    // Revert keys list mutations. The PKCS #11 provider list was already saved.
    QString error;
    if (tls_session_key_files_model_->revertChanges(error) && !error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    }
}
