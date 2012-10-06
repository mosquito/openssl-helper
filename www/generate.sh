#!/bin/sh

#--------------------------------------------------------
DAYS=3650
CERT_NAME=$1
KEY_SIZE=2048
DH_KEY_SIZE=${KEY_SIZE}

#--------------------------------------------------------
export C="US"
export ST="Unknown"
export L="Unknown"
export O="Paranoid"
export OU="Security"
export CN=${CERT_NAME}
#--------------------------------------------------------
_dirs="private private/crl private/certdb private/keys private/arc"

for dir in $_dirs
    do
        if test -d $dir
            then echo "\tDirectory $dir is exist"
            else mkdir -p $dir
        fi
done

chmod 700 private

if test -f private/serial
    then echo "File \"serial\" is exist"
    else echo 01 > private/serial
fi

if test -f private/index
    then echo "File \"index\" is exist"
    else touch private/index
fi

if test -f private/CA_key.crt && test -f private/CA_cert.crt && test -f private/dh${DH_KEY_SIZE}.pem
    then
        if [ -n "$1" ]
            then
                echo "Generating $1 keyfiles"

                # Создание сертификата сервера
                openssl req -config openssl.conf -new -nodes -keyout private/keys/${CERT_NAME}.key -out private/keys/${CERT_NAME}.csr -newkey rsa:${KEY_SIZE} || exit 1

                # Для создания сертификата сервера необходимо подписать запрос на сертификат сервера  самоподписным доверенным сертификатом (CA).
                openssl ca -batch -config openssl.conf -out private/keys/${CERT_NAME}.cert -infiles private/keys/${CERT_NAME}.csr
                # Просмотр результата генерации сертификата
                openssl x509 -noout -text -in private/keys/${CERT_NAME}.cert

                cd private
                cat keys/${CERT_NAME}.cert CA_cert.crt >  keys/${CERT_NAME}.chained.crt


                FILES="keys/${CERT_NAME}.csr keys/${CERT_NAME}.key keys/${CERT_NAME}.cert keys/${CERT_NAME}.chained.crt CA_cert.cer CA_cert.crt dh${DH_KEY_SIZE}.pem"
                tar cvpzhf arc/${CERT_NAME}.tar.gz ${FILES}
            else
                echo "\n\nServer key found\n Usage: $0 NewCertName"
                exit 1
        fi
    else
        # Создание самоподписного доверенного сертификата (CA)
        openssl req -config openssl.conf -new -nodes -x509 -extensions CA_extension -keyout private/CA_key.crt -out private/CA_cert.crt -days ${DAYS} -newkey rsa:${KEY_SIZE} || exit 1

        openssl x509 -text -in private/CA_cert.crt -out private/CA_cert.cer

        # Создание файла параметров Диффи-Хэлмана
        openssl dhparam -out private/dh${DH_KEY_SIZE}.pem ${DH_KEY_SIZE} || exit 1

        cd private
        FILES="CA_key.crt CA_cert.crt CA_cert.cer dh${DH_KEY_SIZE}.pem"
        tar cvpzhf arc/${CERT_NAME}.tar.gz ${FILES}
fi
