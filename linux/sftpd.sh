#!/bin/bash
ID=${2:-default}
JAVA_BIN=${JAVA_BIN:-java}
SFTPD_HOME=${SFTPD_HOME:-/opt/sftpd}
SFTPD_MEM_MB=${SFTPD_MEM_MB:-64}
SFTPD_OPTS_DEF="-XX:+IgnoreUnrecognizedVMOptions -XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=20 -verbose:gc -XX:+PrintGCDetails -Xlog:gc*::time,uptime,level,tags -XX:+PrintGCDateStamps -XX:+PrintGCTimeStamps -showversion -XX:+PrintCommandLineFlags -XX:-PrintFlagsFinal"
SFTPD_OPTS="${SFTPD_OPTS:-${SFTPD_OPTS_DEF}}"
SFTPD_JAR="$SFTPD_HOME/lib/sftpserver.jar"
SFTPD_LOG4J="${SFTPD_HOME}/conf/${ID}/log4j.properties"
SFTPD_POLICY_1="${SFTPD_HOME}/conf/${ID}/sftpd.policy" # Custom
SFTPD_POLICY_2="${SFTPD_HOME}/lib/sftpd.policy"        # Generic
LAUNCHER_CLASS="org.springframework.boot.loader.PropertiesLauncher"
PWD_CLASS="org.javastack.sftpserver.PasswordEncrypt"
PIDFILE="${SFTPD_HOME}/pid/sftpd-${ID}.pid"
#
[ -r "$SFTPD_POLICY_2" ] && SFTPD_POLICY="$SFTPD_POLICY_2" # Generic
[ -r "$SFTPD_POLICY_1" ] && SFTPD_POLICY="$SFTPD_POLICY_1" # Custom
#
do_pwd () {
  cd ${SFTPD_HOME}
  ${JAVA_BIN} \
    -Dloader.main=${PWD_CLASS} \
    -cp "${SFTPD_JAR}" ${LAUNCHER_CLASS}
}
do_run () {
  cd ${SFTPD_HOME}
  exec ${JAVA_BIN} -Dprogram.name=sftpd-${ID} ${SFTPD_OPTS} -Xmx${SFTPD_MEM_MB}m \
    -Dsftp.id=$ID -Dsftp.home=$SFTPD_HOME -Dsftp.log=${SFTPD_LOG:-CONSOLE} \
    -Dsftp.config="${SFTPD_HOME}/conf/${ID}/:${SFTPD_HOME}/conf/" \
    -Djava.security.manager -Djava.security.policy=file:"${SFTPD_POLICY}" \
    -Dlog4j.configuration=file:"${SFTPD_LOG4J}" \
    -jar "${SFTPD_JAR}"
}
do_start () {
  cd ${SFTPD_HOME}
  nohup ${JAVA_BIN} -Dprogram.name=sftpd-${ID} ${SFTPD_OPTS} -Xmx${SFTPD_MEM_MB}m \
    -Dsftp.id=$ID -Dsftp.home=$SFTPD_HOME -Dsftp.log=${SFTPD_LOG:-FILE} \
    -Dsftp.config="${SFTPD_HOME}/conf/${ID}/:${SFTPD_HOME}/conf/" \
    -Djava.security.manager -Djava.security.policy=file:"${SFTPD_POLICY}" \
    -Dlog4j.configuration=file:"${SFTPD_LOG4J}" \
    -jar "${SFTPD_JAR}" 1>${SFTPD_HOME}/log/sftpd-${ID}.bootstrap 2>&1 &
  PID="$!"
  echo ${PID} >$PIDFILE
  echo "SFTPD: STARTED [${PID}]"
}
do_stop () {
  local PID="$(cat $PIDFILE 2>/dev/null)"
  if [ -f "/proc/${PID}/status" ]; then
    echo -n "Stopping SFTPD ${ID} : "
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
    echo Stopping SFTPD ${ID} : NOT FOUND
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
  run)
    do_run
  ;;
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
    echo "$0 <run|start|stop|restart|status|pwd> [id]"
  ;;
esac