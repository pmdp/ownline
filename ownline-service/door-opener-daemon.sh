#!/bin/sh
### BEGIN INIT INFO
# Provides: door-opener-daemon
# Required-Start:
# Should-Start:
# Required-Stop:
# Should-Stop:
# Default-Start:  3 5
# Default-Stop:   0 1 2 6
# Short-Description: Door Opener Daemon
# Description:    Run
### END INIT INFO

case "$1" in
   start)
      echo "Starting server"
      python /usr/local/bin/test.py start
      ;;

   stop)
      echo "Stopping server"
      python /usr/local/bin/test.py stop
      ;;

   restart)
      echo "Restarting server"
      python /usr/local/bin/test.py restart
      ;;

   *)
      echo "Usage: /etc/init.d/door-opener-daemon.sh {start|stop|restart}"
      exit 1
      ;;
esac
exit 0