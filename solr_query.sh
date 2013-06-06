#!/bin/sh
CMD=$1
ARG=$2
case "$CMD" in
  "ping")
    PATH_INFO="/admin/ping" php search-proxy.php
    ;;
  "schema")
    PATH_INFO="/admin/luke" QUERY_STRING="show=schema" php search-proxy.php
    ;;
  "file")
    PATH_INFO="/admin/file" QUERY_STRING="contentType=text/xml;charset=utf-8&file=$ARG" php search-proxy.php
    ;;
  "search")
    PATH_INFO="/select" QUERY_STRING="q=$ARG" php search-proxy.php
    ;;
  *)
    echo "Unknown command."
    echo "Available commands:"
    grep -Eo '"[a-z]+")' $0 | tr -cd "[a-z\n]" | xargs
esac
