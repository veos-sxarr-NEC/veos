#!/bin/sh

in="$1"
out1="$2"
out2="$3"

grep '^[0-9]' "$in" | sort -n | (
    while read nr name block handler; do
	    echo "VE_SYSCALL($nr, $name, $block, $handler)"
    done
) > "$out1"

grep '^[0-9]' "$in" | sort -n | (
    while read nr name handler; do
	if [ "$handler" != "NULL" ] && [ "$handler" != "ve_generic_offload" ]; then
		echo "ret_t $name(int , char *, veos_handle *);"
	fi
    done
) > "$out2"
