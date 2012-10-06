#!/bin/bash

GEN_MC=gen-mc/gen-mc_`uname -m`
DISPLAY_NAME=$1
USER_ID=$2
EXPIRY=3650
WRITE_CERT=private/linksys/${DISPLAY_NAME}.mini_cert
WRITE_PK=private/linksys/${DISPLAY_NAME}.mini_pkey

${GEN_MC} -k private/CA_key.pem -d ${DISPLAY_NAME} -u ${USER_ID} -E ${EXPIRY} -o "${WRITE_CERT}" -p "${WRITE_PK}" -v
