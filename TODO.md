# Add reporting output

    for i in $(ls -v); do echo $(echo $i | cut -d'-' -f2) - $(wc -l $i | cut -d' ' -f1 ); done | column
