// Copyright (c) 2017-2018 The CruZeta developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_LITECOINZADDRESSVALIDATOR_H
#define BITCOIN_QT_LITECOINZADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class CruZetaAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CruZetaAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** CruZeta address widget validator, checks for a valid cruzeta address.
 */
class CruZetaAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CruZetaAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // BITCOIN_QT_LITECOINZADDRESSVALIDATOR_H
