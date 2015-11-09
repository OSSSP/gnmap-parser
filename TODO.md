# Add reporting output

    for i in $(ls -v); do echo $(echo $i | cut -d'-' -f2)/$(echo $i | cut -d'-' -f3| sed 's/.txt//') - $(wc -l $i | cut -d' ' -f1 ); done | colum

