#!/usr/bin/env bash
# يبني النسخة الجاهزة للتشغيل في جذر الريبو (MonsterASP يعمل git clone مباشرة بدون build)
set -e
cd "$(dirname "$0")"
rm -rf /tmp/nqpub
dotnet publish source/NqCert -c Release -o /tmp/nqpub -p:UseAppHost=false
find /tmp/nqpub/runtimes -mindepth 1 -maxdepth 1 ! -name 'win*' -exec rm -rf {} +
rm -f /tmp/nqpub/*.pdb
cp -r /tmp/nqpub/. .
echo "تم البناء — اعمل commit و push ثم Pull من لوحة MonsterASP"
