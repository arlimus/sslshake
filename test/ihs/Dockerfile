FROM jamielcoleman/ihs:v1

RUN apt-get install vim -y && \
    mkdir -p /opt/IBM/HTTPServer/ssl && \
    mkdir -p /opt/IBM/HTTPServer/www && \
    mkdir -p /opt/IBM/HTTPServer/conf.d && \
    /opt/IBM/HTTPServer/bin/gskcapicmd -keydb -create -db /opt/IBM/HTTPServer/ssl/mykey.kdb -pw myPASS4 -type cms -stash && \
    /opt/IBM/HTTPServer/bin/gskcapicmd -cert -create -db /opt/IBM/HTTPServer/ssl/mykey.kdb -pw myPASS4 -label TDSSRV_CERT -dn "CN=`hostname`,O=IBM,C= EU" -default_cert yes -expire 365 -size 2048 && \
    echo 'Include conf.d/*.conf' >> /opt/IBM/HTTPServer/conf/admin.conf && \
    /opt/IBM/HTTPServer/bin/adminctl configtest

ADD ssl.conf /opt/IBM/HTTPServer/conf.d/
ADD entrypoint.sh /

RUN chmod +x /*.sh

CMD ["/entrypoint.sh"]
