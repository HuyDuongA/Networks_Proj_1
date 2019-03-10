#!/bin/bash

for f in trace_files/*.txt
    do echo Run $f && ./trace $f
    if [ $? -eq 139 ]; then
        echo "Crashed at $f"
        exit 1
    fi
done > out.txt

diff expect.txt out.txt > diff.txt | cat
