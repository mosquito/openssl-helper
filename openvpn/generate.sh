#!/bin/bash

#--------------------------------------------------------
DAYS=3650
#HOSTNAME=`hostname`
HOSTNAME=vpn
KEY_SIZE=2048
DH_KEY_SIZE=${KEY_SIZE}

#TYPE=tun
TYPE=tap

#--------------------------------------------------------
export C="US"
export ST="Unknown State"
export L="Unknown"
export O="Paranoid Inc."
export OU="Security"
export CN=${HOSTNAME}
#--------------------------------------------------------
_dirs="private private/crl private/certdb private/keys private/req private/certs private/arc"

function reverse {
    P="private"
    FILES="req/$1.csr keys/$1.key certs/$1.cert $1_tcp.conf $1_udp.conf $1_tcp.ovpn $1_udp.ovpn arc/$1.tar.gz"

    S=`openssl x509 -in private/certdb/$(cat private/serial).pem -noout -subject | awk 'BEGIN {FS = "/"} ;{print $4}' | tr -d "CN="`
    SO=`openssl x509 -in private/certdb/$(cat private/serial.old).pem -noout -subject | awk 'BEGIN {FS = "/"} ;{print $4}' | tr -d "CN="`

    if [ "$S" = "$1" ]
        then
            rm $P/certdb/$(cat private/serial).pem
    fi

    if [ "$SO" = "$1" ]
        then
            rm $P/certdb/$(cat private/serial.old).pem
    fi

    mv $P/index.attr.old $P/index.attr  > /dev/null 2>&1
    mv $P/index.old $P/index  > /dev/null 2>&1
    mv $P/serial.old $P/serial  > /dev/null 2>&1

    for file in $FILES
        do rm $P/$file > /dev/null 2>&1
    done

    echo "Restoring previous state"
    exit 2
}

for dir in $_dirs
    do
        if test -d $dir
            then echo "	Directory $dir is exist"
            else mkdir -p $dir
        fi
done

chmod 700 -R private/keys

if test -f private/serial
    then echo "File \"serial\" is exist"
    else echo 01 > private/serial
fi

if test -f private/index
    then echo "File \"index\" is exist"
    else touch private/index
fi

if test -f private/CA_key.pem && \
   test -f private/CA_key.pem && \
   test -f private/keys/${HOSTNAME}.key && \
   test -f private/certs/${HOSTNAME}.cert && \
   test -f private/req/${HOSTNAME}.csr
    then
        if [ -n "$1" ]
            then
                if [ "$1" = "-r" ]
                    then
                        openssl ca -config openssl.conf -revoke private/certs/$2.cert
                        openssl ca -gencrl -config openssl.conf -out private/crl/crl.pem
                else
                    echo "Generating $1 keyfiles"
                    export CN=$1
                    openssl req -new -nodes -config openssl.conf -keyout private/keys/$1.key -out private/req/$1.csr || reverse $1
                    openssl ca -batch -config openssl.conf -out private/certs/$1.cert -infiles private/req/$1.csr || reverse $1

                    cd private

                    python ../makeconf.py client ${HOSTNAME} $1 udp ${TYPE} > "$1"_udp.conf
                    python ../makeconf.py client ${HOSTNAME} $1 tcp ${TYPE} > "$1"_tcp.conf

                    python ../makeconf.py clientwin ${HOSTNAME} $1 udp ${TYPE} > "$1"_udp.ovpn
                    python ../makeconf.py clientwin ${HOSTNAME} $1 tcp ${TYPE} > "$1"_tcp.ovpn

                    FILES="req/$1.csr keys/$1.key certs/$1.cert ta.key CA_cert.pem $1_tcp.conf $1_udp.conf $1_tcp.ovpn $1_udp.ovpn"
                    tar cvzhf arc/$1.tar.gz ${FILES} || reverse $1

                    rm $1_tcp.conf $1_udp.conf $1_tcp.ovpn $1_udp.ovpn
                fi
            else
                echo "\n\nServer key found\n Usage: $0 NewCertName"
                exit 1
        fi
    else
        # Создание самоподписного доверенного сертификата (CA)
        openssl req -config openssl.conf -new -nodes -x509 -keyout private/CA_key.pem -out private/CA_cert.pem -days ${DAYS} -newkey rsa:${KEY_SIZE} || exit 1

        # Создание сертификата сервера
        openssl req -config openssl.conf -new -nodes -keyout private/keys/${HOSTNAME}.key -out private/req/${HOSTNAME}.csr -newkey rsa:${KEY_SIZE} || exit 1

        # Для создания сертификата сервера необходимо подписать запрос на сертификат сервера  самоподписным доверенным сертификатом (CA).
        openssl ca -batch -config openssl.conf -extensions server -out private/certs/${HOSTNAME}.cert -infiles private/req/${HOSTNAME}.csr
        # Просмотр результата генерации сертификата
        openssl x509 -noout -text -in private/certs/${HOSTNAME}.cert

        # Создание файла параметров Диффи-Хэлмана
        openssl dhparam -out private/dh${DH_KEY_SIZE}.pem ${DH_KEY_SIZE} || exit 1

        openssl ca -gencrl -config openssl.conf -out private/crl/crl.pem

        # TLS Auth
        /usr/sbin/openvpn --genkey --secret private/ta.key || exit 1

        cd private

        python ../makeconf.py server ${HOSTNAME} ${DH_KEY_SIZE} udp ${TYPE} > server_udp.conf
        python ../makeconf.py server ${HOSTNAME} ${DH_KEY_SIZE} tcp ${TYPE} > server_tcp.conf

        FILES="req/${HOSTNAME}.csr keys/${HOSTNAME}.key certs/${HOSTNAME}.cert dh${DH_KEY_SIZE}.pem ta.key CA_cert.pem server_tcp.conf server_udp.conf crl/crl.pem"
        tar cvzhf arc/${HOSTNAME}.tar.gz ${FILES}
fi
