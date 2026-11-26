#!/usr/bin/env bash
# 服务统一控制： ./scripts/ctl.sh {start|stop|restart|status|logs}
set -u
UNITS="privsrv agentsrv privsrv-admin privsrv-proxy privsrv-dns privsrv-dot"
case "${1:-status}" in
  start)   for u in $UNITS; do systemctl start "$u"; done ;;
  stop)    for u in $UNITS; do systemctl stop "$u"; done ;;
  restart) for u in $UNITS; do systemctl restart "$u"; done ;;
  status)  systemctl status $UNITS --no-pager -l 2>/dev/null | grep -E '●|Active:|Main PID' || systemctl is-active $UNITS ;;
  logs)    echo "--- 后端 ---"; journalctl -u privsrv -n 15 --no-pager 2>/dev/null
           echo "--- 代理 ---"; journalctl -u privsrv-proxy -n 15 --no-pager 2>/dev/null
           echo "--- WS ---";   journalctl -u agentsrv -n 15 --no-pager 2>/dev/null ;;
  *) echo "用法: $0 {start|stop|restart|status|logs}" ;;
esac
