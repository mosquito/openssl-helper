Openvpn
=======

Prepare to production
---------------------
1. Edit makeconf.py for you networks (edit SERVER_TEMPLATE)
2. Run "./generate" without params first time for generate server cert and configs
3. Edit makeconf.py for clients configs (edit CLIENT_TEMPLATE)

Create Client Cert
------------------
1. Run "./generate Client001" for generating keys for name client "Client001"
2. See certdb for you sertificate archive

Revocation Cert
---------------
1. Run "./generate.sh -r Client001"
2. Copy private/crl/crl.pem to you openvpn server config dir.