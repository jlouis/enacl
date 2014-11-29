#!/bin/bash

case $1 in
	"on" )
		for i in /sys/devices/system/cpu/cpu[0-7] ; do
			echo performance > $i/cpufreq/scaling_governor
		done;;
	"off" )
		for i in /sys/devices/system/cpu/cpu[0-7] ; do
			echo powersave > $i/cpufreq/scaling_governor
		done;;
	*)
		echo "Usage: $0 on|off";;
esac

