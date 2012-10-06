#!/bin/sh

#--------------------------------------------------------
DAYS=3650
HOSTNAME=`hostname`
KEY_SIZE=512
CA_KEY_SIZE=1024
DH_KEY_SIZE=${KEY_SIZE}

#--------------------------------------------------------
export C="US"
export ST="Unknown State"
export L="Unknown"
export O="Paranoid Inc."
export OU="Security"
export CN=${HOSTNAME}
#--------------------------------------------------------
_dirs="private private/crl private/certdb private/linksys private/keys private/req private/certs private/arc"

for dir in $_dirs
    do
        if test -d $dir
            then echo "\tDirectory $dir is exist"
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
   test -f private/CA_cert.pem && \
   test -f private/keys/${HOSTNAME}.key && \
   test -f private/certs/${HOSTNAME}.cert && \
   test -f private/req/${HOSTNAME}.csr && \
   test -f private/keys/${HOSTNAME}.pem
    then
        if [ -n "$1" ]:
            then
		export CN=$1
                openssl genrsa -out private/keys/$1.key ${KEY_SIZE} || exit 1
                openssl req -config openssl.conf -new -nodes -keyout private/keys/$1.key -out private/req/$1.csr -newkey rsa:${KEY_SIZE} || exit 1
                openssl x509 -req -days ${DAYS} -in private/req/$1.csr -CA private/CA_cert.pem -CAkey private/CA_key.pem -set_serial 01 -out private/certs/$1.cert || exit 1
                echo "\n\tCombining key and crt into $1.pem"
                cat private/keys/$1.key > private/keys/$1.pem || exit 1
                cat private/certs/$1.cert >> private/keys/$1.pem || exit 1

                cd private
                FILES="req/$1.csr keys/$1.key keys/$1.pem certs/$1.cert CA_cert.pem"
                tar cvpzhf arc/$1.tar.gz ${FILES}
            else
                echo "\n\nServer key found\n Usage: $0 NewCertName"
                exit 1
        fi
    else
        openssl genrsa -out private/CA_key.pem ${CA_KEY_SIZE} || exit 1
        openssl req -new -config openssl.conf -x509 -days ${DAYS} -key private/CA_key.pem -out private/CA_cert.pem || exit 1

        openssl genrsa -out private/keys/${HOSTNAME}.key ${KEY_SIZE} || exit 1
        openssl req -config openssl.conf -new -nodes -keyout private/keys/${HOSTNAME}.key -out private/req/${HOSTNAME}.csr -newkey rsa:${KEY_SIZE} || exit 1
        openssl x509 -req -days ${DAYS} -in private/req/${HOSTNAME}.csr -CA private/CA_cert.pem -CAkey private/CA_key.pem -set_serial 01 -out private/certs/${HOSTNAME}.cert || exit 1
        echo "\n\tCombining key and crt into ${HOASTNAME}.pem"
        cat private/keys/${HOSTNAME}.key > private/keys/${HOSTNAME}.pem || exit 1
        cat private/certs/${HOSTNAME}.cert >> private/keys/${HOSTNAME}.pem || exit 1

        cd private
        FILES="req/${HOSTNAME}.csr keys/${HOSTNAME}.key keys/${HOSTNAME}.pem certs/${HOSTNAME}.cert CA_key.pem CA_cert.pem"
        tar cvpzhf arc/${HOSTNAME}.tar.gz ${FILES}
fi


