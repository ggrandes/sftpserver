#!/bin/bash
JAVA_HOME=${JAVA_HOME:-/opt/java/java-current}
SFTPD_HOME=${SFTPD_HOME:-/opt/sftpd}
SFTPD_CLASSPATH=$(echo $SFTPD_HOME/lib/*.jar | tr ' ' ':')
SFTPD_POLICY="file:${SFTPD_HOME}/lib/sftpd.policy"
ID=${2:-default}
MAIN_CLASS="org.javastack.sftpserver.Server"
PWD_CLASS="org.javastack.sftpserver.PasswordEncrypt"
PIDFILE="${SFTPD_HOME}/pid/sftpd-${ID}.pid"
#
do_pwd () {
  cd ${SFTPD_HOME}
  ${JAVA_HOME}/bin/java \
    -cp "${SFTPD_CLASSPATH}" \
    ${PWD_CLASS}
}
do_start () {
  cd ${SFTPD_HOME}
  nohup ${JAVA_HOME}/bin/java -Dprogram.name=sftpd -Xmx64m \
    -Dsftp.id=$ID -Dsftp.home=$SFTPD_HOME \
    -cp "${SFTPD_HOME}/conf/${ID}/:${SFTPD_HOME}/conf/:${SFTPD_CLASSPATH}" \
    -Djava.security.manager -Djava.security.policy=${SFTPD_POLICY} \
    ${MAIN_CLASS} 1>${SFTPD_HOME}/log/sftpd-${ID}.bootstrap 2>&1 &
  PID="$!"
  echo ${PID} >$PIDFILE
  echo "SFTPD: STARTED [${PID}]"
}
do_stop () {
  local PID="$(cat $PIDFILE 2>/dev/null)"
  if [ -f "/proc/${PID}/status" ]; then
    echo -n "Stoping SFTPD ${ID} : "
    kill -TERM $PID
    local _cnt=0
    while [ -f "/proc/${PID}/status" ]; do {
      echo -n "."
      if [ "$_cnt" -gt "5" ]; then
        kill -KILL $PID
        break;
      fi
      _cnt=$[$_cnt + 1];
      sleep 1;
    } done
    echo " OK"
  else
    echo Stoping SFTPD ${ID} : NOT FOUND
  fi
  rm -f $PIDFILE 1>/dev/null 2>&1
}
do_status () {
  local PID="$(cat $PIDFILE 2>/dev/null)"
  echo -n "Status SFTPD ${ID} : "
  if [ -f "$PIDFILE" -a -d "/proc/${PID}/fd/" ]; then
    echo "RUNNING [${PID}]"
  else
    echo "NOT RUNNING"
  fi
}
case "$1" in
  start)
    do_stop
    do_start
  ;;
  stop)
    do_stop
  ;;
  restart)
    do_stop
    do_start
  ;;
  status)
    do_status
  ;;
  pwd)
    do_pwd
  ;;
  *)
    echo "$0 <start|stop|restart|status|pwd> [id]"
  ;;
esac