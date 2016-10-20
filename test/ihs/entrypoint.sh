#!/bin/bash -ex

/opt/IBM/HTTPServer/bin/adminctl restart
cat /opt/IBM/HTTPServer/logs/admin_error.log
tail -f /opt/IBM/HTTPServer/logs/admin_access_log
