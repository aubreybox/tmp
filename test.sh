#!/bin/bash
LS_PATH=/usr/share/logstash/bin/logstash

LS_JAVA_OPTS="-Djava.security.debug=all -Djavax.net.debug=all" 

# for certificates
# CURVE=secp521r1 # NO SHARED CIPHER
# CURVE=secp160r1 # UNKNOWN_GROUP
# CURVE=secp384r1 # NO_SHARED_CIPHER
# CURVE=prime256v1 # Works
# CURVE=Oakley-EC2N-3 # Wont work with openssl + aes (creating root ca key)

# where to store CAs
FOLDER=$(pwd)
PASS=testtest

for CURVE in $(openssl ecparam -list_curves | grep ":"| grep -v Oakley | cut -d " " -f 3|  tr -d ":"); do 
    echo $CURVE
    #create certificates - only if no ca folder is found
    if [ ! -d $FOLDER/ca ]
    then
        ## root ca
        mkdir -p $FOLDER/ca/{certs,crl,newcerts,private}
        touch $FOLDER/ca/index.{rsa,ecc}.txt
        echo 1000 > $FOLDER/ca/serial

        #create root ca keys
        openssl genrsa -aes256 -passout pass:$PASS -out $FOLDER/ca/private/ca.rsa.key.pem 4096 
        openssl ecparam -name $CURVE -genkey | openssl ec -aes256 -passout pass:$PASS -out $FOLDER/ca/private/ca.ecc.key.pem

        #copy root ca configs
        wget https://raw.githubusercontent.com/aubreybox/tmp/master/openssl.rsa.cnf -O $FOLDER/ca/openssl.rsa.cnf
        wget https://raw.githubusercontent.com/aubreybox/tmp/master/openssl.ecc.cnf -O $FOLDER/ca/openssl.ecc.cnf

        sed -i "s-/root/test-$FOLDER-g" $FOLDER/ca/openssl.rsa.cnf
        sed -i "s-/root/test-$FOLDER-g" $FOLDER/ca/openssl.ecc.cnf

        #sign root ca certs
        openssl req -config $FOLDER/ca/openssl.rsa.cnf -key $FOLDER/ca/private/ca.rsa.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out $FOLDER/ca/certs/ca.rsa.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=root ca rsa"
        openssl req -config $FOLDER/ca/openssl.ecc.cnf -key $FOLDER/ca/private/ca.ecc.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out $FOLDER/ca/certs/ca.ecc.cert.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=root ca ecc"

        openssl pkcs12 -export -inkey $FOLDER/ca/private/ca.rsa.key.pem -in $FOLDER/ca/certs/ca.rsa.cert.pem -name ca.rsa.cert.pem -passin file:<(echo -n "$PASS") -out $FOLDER/ca/private/ca.rsa.cert.p12  -passout pass:$PASS
        openssl pkcs12 -export -inkey $FOLDER/ca/private/ca.ecc.key.pem -in $FOLDER/ca/certs/ca.ecc.cert.pem -name ca.ecc.cert.pem -passin file:<(echo -n "$PASS") -out $FOLDER/ca/private/ca.ecc.cert.p12  -passout pass:$PASS

        ## intermediate ca
        mkdir -p $FOLDER/ca/intermediate/{certs,crl,csr,newcerts,private}
        touch $FOLDER/ca/intermediate/index.{rsa,ecc}.txt
        echo 1000 > $FOLDER/ca/intermediate/serial
        echo 1000 > $FOLDER/ca/intermediate/crlnumber

        #create intermediate ca keys
        openssl genrsa -aes256 -passout pass:$PASS -out $FOLDER/ca/intermediate/private/intermediate.rsa.key.pem 4096
        openssl ecparam -name $CURVE -genkey  | openssl ec -aes256 -passout pass:$PASS -out $FOLDER/ca/intermediate/private/intermediate.ecc.key.pem

        #copy intermediate ca configs
        wget https://raw.githubusercontent.com/aubreybox/tmp/master/intermediate/openssl.rsa.cnf -O $FOLDER/ca/intermediate/openssl.rsa.cnf
        wget https://raw.githubusercontent.com/aubreybox/tmp/master/intermediate/openssl.ecc.cnf -O $FOLDER/ca/intermediate/openssl.ecc.cnf
        sed -i "s-/root/test-$FOLDER-g" $FOLDER/ca/intermediate/openssl.rsa.cnf
        sed -i "s-/root/test-$FOLDER-g" $FOLDER/ca/intermediate/openssl.ecc.cnf

        #sign intermediate ca certs
        openssl req -config $FOLDER/ca/intermediate/openssl.rsa.cnf -new -sha256 -key $FOLDER/ca/intermediate/private/intermediate.rsa.key.pem -out $FOLDER/ca/intermediate/csr/intermediate.rsa.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=intermediate ca rsa"
        openssl req -config $FOLDER/ca/intermediate/openssl.ecc.cnf -new -sha256 -key $FOLDER/ca/intermediate/private/intermediate.ecc.key.pem -out $FOLDER/ca/intermediate/csr/intermediate.ecc.csr.pem -passin file:<(echo -n "$PASS") -subj "/C=US/ST=test/L=test/O=test/CN=intermediate ca ecc"

        openssl ca -config $FOLDER/ca/openssl.rsa.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in $FOLDER/ca/intermediate/csr/intermediate.rsa.csr.pem -out $FOLDER/ca/intermediate/certs/intermediate.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
        openssl ca -config $FOLDER/ca/openssl.ecc.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in $FOLDER/ca/intermediate/csr/intermediate.ecc.csr.pem -out $FOLDER/ca/intermediate/certs/intermediate.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch

        openssl pkcs12 -export -inkey $FOLDER/ca/intermediate/private/intermediate.rsa.key.pem -in $FOLDER/ca/intermediate/certs/intermediate.rsa.cert.pem -name intermediate.rsa.cert.pem -passin file:<(echo -n "$PASS") -out $FOLDER/ca/intermediate/private/intermediate.rsa.cert.p12  -passout pass:$PASS
        openssl pkcs12 -export -inkey $FOLDER/ca/intermediate/private/intermediate.ecc.key.pem -in $FOLDER/ca/intermediate/certs/intermediate.ecc.cert.pem -name intermediate.ecc.cert.pem -passin file:<(echo -n "$PASS") -out $FOLDER/ca/intermediate/private/intermediate.ecc.cert.p12  -passout pass:$PASS

        # server cert
        # create server key
        openssl genrsa -out $FOLDER/ca/intermediate/private/localhost.rsa.key.pem 2048
        openssl ecparam -name $CURVE -genkey -out $FOLDER/ca/intermediate/private/localhost.ecc.key.pem 

        #create csr
        openssl req -config $FOLDER/ca/intermediate/openssl.rsa.cnf -key $FOLDER/ca/intermediate/private/localhost.rsa.key.pem -new -sha256 -out $FOLDER/ca/intermediate/csr/localhost.rsa.csr.pem -subj "/C=US/ST=test/L=test/O=test/CN=localhost"
        openssl req -config $FOLDER/ca/intermediate/openssl.ecc.cnf -key $FOLDER/ca/intermediate/private/localhost.ecc.key.pem -new -sha256 -out $FOLDER/ca/intermediate/csr/localhost.ecc.csr.pem -subj "/C=US/ST=test/L=test/O=test/CN=localhost"

        #sign csr
        openssl ca -config $FOLDER/ca/intermediate/openssl.rsa.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in $FOLDER/ca/intermediate/csr/localhost.rsa.csr.pem -out $FOLDER/ca/intermediate/certs/localhost.rsa.cert.pem -passin file:<(echo -n "$PASS") -batch
        openssl ca -config $FOLDER/ca/intermediate/openssl.ecc.cnf -extensions server_cert -batch -days 375 -notext -md sha256 -in $FOLDER/ca/intermediate/csr/localhost.ecc.csr.pem -out $FOLDER/ca/intermediate/certs/localhost.ecc.cert.pem -passin file:<(echo -n "$PASS") -batch

        # check
        # chain root / intermediate
        cat $FOLDER/ca/intermediate/certs/intermediate.rsa.cert.pem $FOLDER/ca/certs/ca.rsa.cert.pem > $FOLDER/ca/intermediate/certs/ca-chain.rsa.cert.pem
        cat $FOLDER/ca/intermediate/certs/intermediate.ecc.cert.pem $FOLDER/ca/certs/ca.ecc.cert.pem > $FOLDER/ca/intermediate/certs/ca-chain.ecc.cert.pem

        openssl verify -CAfile $FOLDER/ca/intermediate/certs/ca-chain.rsa.cert.pem  $FOLDER/ca/intermediate/certs/localhost.rsa.cert.pem
        if [ $? -ne 0 ]
        then
            echo "certificates not verifiable"
            exit 1
        fi
        openssl verify -CAfile $FOLDER/ca/intermediate/certs/ca-chain.ecc.cert.pem  $FOLDER/ca/intermediate/certs/localhost.ecc.cert.pem
        if [ $? -ne 0 ]
        then
            echo "certificates not verifiable"
            exit 1
        fi

        openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in $FOLDER/ca/intermediate/private/localhost.rsa.key.pem -out $FOLDER/ca/intermediate/private/localhost.rsa.pkcs8.key
        openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in $FOLDER/ca/intermediate/private/localhost.ecc.key.pem -out $FOLDER/ca/intermediate/private/localhost.ecc.pkcs8.key
    fi
    # / create certificates
    ## LS

    #copy logstash config - only if not already there
    mkdir -p $FOLDER/out/$CURVE/
    mkdir -p $FOLDER/ls_data_{rsa,ecc}
    if [ ! -f $FOLDER/ls.conf ]
    then
        wget https://raw.githubusercontent.com/aubreybox/tmp/master/ls.conf -O $FOLDER/ls.conf
        sed -i "s-/root/test-$FOLDER-g" $FOLDER/ls.conf

    fi

    #start tcpdump
    tcpdump -w $FOLDER/out/$CURVE/hs.cap -i lo port 5050 or port 5051 -U &
    TD_PID=$!

    #start logstash
    $LS_PATH --config.debug --path.data $FOLDER/ls_data_rsa --log.level=debug -f $FOLDER/ls.conf -l $FOLDER/ &> $FOLDER/out/$CURVE/ls.rsa.out &
    LS_PID=$!

    #wait for logstash to be ready
    until ss -nptl | grep -qE "\:505[01]"
    do 
        sleep 1
        echo "waiting for logstash to be ready"
    done

    #connect to logstash via rsa certificate
    echo | timeout 3  openssl s_client  -msg -CAfile $FOLDER/ca/intermediate/certs/ca-chain.rsa.cert.pem  -cert $FOLDER/ca/intermediate/certs/localhost.rsa.cert.pem -key $FOLDER/ca/intermediate/private/localhost.rsa.pkcs8.key  -servername localhost -state -tls1_2 -connect localhost:5050 -cipher ECDHE-RSA-AES256-GCM-SHA384 2>&1 | tee $FOLDER/out/$CURVE/openssl.rsa.log

    kill $LS_PID 

    while ss -nptl | grep -qE "\:505[01]"
    do 
        sleep 1
        echo "waiting for logstash to shutdown"
    done

    #start logstash
    $LS_PATH --config.debug --path.data $FOLDER/ls_data_ecc --log.level=debug -f $FOLDER/ls.conf -l $FOLDER/ &> $FOLDER/out/$CURVE/ls.ecc.out &
    LS_PID=$!

    #wait for logstash to be ready
    until ss -nptl | grep -qE "\:505[01]"
    do 
        sleep 1
        echo "waiting for logstash to be ready"
    done

    #connect to logstash via ecc certificate
    echo | timeout 3 openssl s_client  -msg -CAfile $FOLDER/ca/intermediate/certs/ca-chain.ecc.cert.pem  -cert $FOLDER/ca/intermediate/certs/localhost.ecc.cert.pem -key $FOLDER/ca/intermediate/private/localhost.ecc.pkcs8.key  -servername localhost -state -tls1_2 -connect localhost:5051 -cipher ECDHE-ECDSA-AES256-GCM-SHA384  2>&1 | tee $FOLDER/out/$CURVE/openssl.ecc.log

    # sleep - otherwise the tcpdump could be empty
    echo "Waiting 3 seconds to exit"
    sleep 3

    #kill logstash and tcpdump
    kill -2 $TD_PID
    kill $LS_PID
    
    while ss -nptl | grep -qE "\:505[01]"
    do 
        sleep 1
        echo "waiting for logstash to shutdown before changing the curve"
    done
    rm -rv $FOLDER/ca
done
# /curve


