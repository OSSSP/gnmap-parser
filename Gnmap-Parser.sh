#!/bin/bash

# Global Variables
parsedir=Gnmap-Parser-Results
portldir=${parsedir}/Port-Lists
portfdir=${parsedir}/Port-Files
portmdir=${parsedir}/Port-Matrix
hostldir=${parsedir}/Host-Lists
hosttype=${parsedir}/Host-Type
thrdprty=${parsedir}/Third-Party
ipsorter='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# Title Function
func_title(){
  # Clear (For Prettyness)
  clear

  # Print Title
  echo '============================================================================'
  echo ' Gnmap-Parser.sh | [Version]: 3.3.4 | [Updated]: 03.06.2014'
  echo '============================================================================'
  echo
}

# Gather Gnmap Files Function
func_gather(){
  echo '[?] Enter The Parent Directory Where Your Gnmap Files Are Located.'
  echo
  read -p '[>] Parent Directory: ' floc
  func_title
  echo '[*] Gathering .gnmap Files'
  find ${floc} -name *.gnmap -exec cp {} . \; >>/dev/null 2>&1
  func_title
  echo "[*] Gathered `ls *.gnmap|wc -l` .gnmap Files"
  echo
  exit 0
}

# Heuristic Gather Gnmap Files Function
func_heuristic(){
  echo '[?] Enter The Parent Directory Where Your Gnmap Files Are Located.'
  echo
  read -p '[>] Parent Directory: ' floc
  script=`echo ${0}|sed -e 's:./::g'`
  func_title
  echo '[*] Heuristically Gathering .gnmap Files'
  greppr=`find ${floc} -type f -not -name ${script} -exec grep -Hlrz "# Nmap.*scan initiated.*as: nmap.*Host:.*(.*).*Status:" {} \;`
  for i in `echo ${greppr}`
  do
    filename=`echo ${i}|sed -e "s:.*/::g" -e 's/.gnmap//'`
    cp ${i} ./${filename}.gnmap >>/dev/null 2>&1
  done
  func_title
  echo "[*] Gathered `ls *.gnmap|wc -l` .gnmap Files"
  echo
  exit 0
}

# Function To Parse .gnmap Files
func_parse(){
  # Check For .gnmap Files Before Parsing
  fcheck=`ls|grep ".gnmap"|wc -l`
  if [ "${fcheck}" -lt '1' ]; then
    echo '[Failed]: No Gnmap Files Found (*.gnmap).'
    echo
    echo '--[ Possible Fixes ]--'
    echo
    echo '[1]: If all of your gnmap files have the correct extension, use option (-g).'
    echo '[2]: If some of your gnmap files dont have the extension, use option (-h).'
    echo '[3]: Place this script in a directory with all relevant *.gnmap files.'
    echo
    exit 1
  fi

  # Create Parsing Directories If Non-Existent
  echo '[*] Preparing Directories...'
  for d in ${parsedir} ${portldir} ${portfdir} ${portmdir} ${hostldir} ${hosttype} ${thrdprty}
  do
    if [ ! -d ${d} ]; then
        mkdir ${d}
    fi
  done

  # Build Alive Hosts Lists
  func_title
  echo '[*] Building Alive Hosts Lists...'
  cat *.gnmap|awk '!/^#|Status: Down/'|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/Alive-Hosts-ICMP.txt
  cat *.gnmap|awk '!/^#/'|grep "open/"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/Alive-Hosts-Open-Ports.txt

  # Build Host-Type Lists
  func_title
  echo '[*] Building Host-Type Windows List...'
  WINRULE01=`cat *.gnmap|grep "445/open/tcp"|grep -v "22/open/tcp"|cut -d" " -f2`
  WINRULE02=`cat *.gnmap|grep "135/open/tcp"|grep -v "445/open/tcp"| cut -d" " -f2`
  WINRULE03=`cat *.gnmap|grep "445/open/tcp"|grep "3389/open/tcp"|cut -d" " -f2`
  echo ${WINRULE01} ${WINRULE02} ${WINRULE03}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Windows.txt

  func_title
  echo '[*] Building Host-Type UNIX/Linux List...'
  NIXRULE01=`cat *.gnmap|grep "22/open/tcp"|grep -v "23/open/tcp"|cut -d" " -f2`
  NIXRULE02=`cat *.gnmap|grep "111/open/tcp"|grep -v "445/open/tcp"|cut -d" " -f2`
  echo ${NIXRULE01} ${NIXRULE02}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Nix.txt

  func_title
  echo '[*] Building Host-Type Webservers List...'
  WEBRULE01=`cat *.gnmap|grep "80/open/tcp"|cut -d" " -f2`
  WEBRULE02=`cat *.gnmap|grep "443/open/tcp"|cut -d" " -f2`
  echo ${WEBRULE01} ${WEBRULE02}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Webservers.txt

  func_title
  echo '[*] Building Host-Type Network Devices List...'
  NETRULE01=`cat *.gnmap|grep "80/open/tcp"|grep "23/open/tcp"|grep "22/open/tcp"|grep -v "445/open/tcp"|cut -d" " -f2`
  echo ${NETRULE01}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Network-Devices.txt

  func_title
  echo '[*] Building Host-Type Printers List...'
  PRNRULE01=`cat *.gnmap|grep "80/open/tcp"|grep "23/open/tcp"|grep "22/open/tcp"|grep "445/open/tcp"|cut -d" " -f2`
  PRNRULE02=`cat *.gnmap|grep "1900/open/tcp"|cut -d" " -f2`
  echo ${PRNRULE01}|tr ' ' '\n'|${ipsorter} > ${hosttype}/Printers.txt

  # Build TCP Ports List
  func_title
  echo '[*] Building TCP Ports List...'
  cat *.gnmap|grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/udp/'|grep "open"|cut -d"/" -f 1|sort -n -u > ${portldir}/TCP-Ports-List.txt

  # Build UDP Ports List
  func_title
  echo '[*] Building UDP Ports List...'
  cat *.gnmap|grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/tcp/'|grep "open"|cut -d"/" -f 1|sort -n -u > ${portldir}/UDP-Ports-List.txt

  # Build TCP Port Files
  for i in `cat ${portldir}/TCP-Ports-List.txt`
  do
    TCPPORT="$i"
    func_title
    echo '[*] Building TCP Port Files...'
    echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${TCPPORT}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/${TCPPORT}-TCP.txt
  done

  # Build UDP Port Files
  for i in `cat ${portldir}/UDP-Ports-List.txt`
  do
    UDPPORT="$i"
    func_title
    echo '[*] Building UDP Port Files...'
    echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${UDPPORT}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/${UDPPORT}-UDP.txt
  done

  # Build TCP Services Matrix
  for i in `cat ${portldir}/TCP-Ports-List.txt`
  do
    TCPPORT="$i"
    func_title
    echo '[*] Building TCP Services Matrix...'
    echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${i}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/$/,TCP,${i}/g"|${ipsorter} >> ${portmdir}/TCP-Services-Matrix.csv
  done

  # Build UDP Services Matrix
  for i in `cat ${portldir}/UDP-Ports-List.txt`
  do
    UDPPORT="$i"
    func_title
    echo '[*] Building UDP Services Matrix...'
    echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${i}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/$/,UDP,${i}/g"|${ipsorter} >> ${portmdir}/UDP-Services-Matrix.csv
  done

  # Build PeepingTom Input File
  for i in `cat ${portldir}/TCP-Ports-List.txt`
  do
    TCPPORT="$i"
    func_title
    echo '[*] Building PeepingTom Input File...'
    echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${i}/open/tcp//http/\| ${i}/open/tcp//http-alt/\| ${i}/open/tcp//http?/\| ${i}/open/tcp//http-proxy/\| ${i}/open/tcp//appserv-http/"|\
                sed -e 's/Host: //g' -e 's/ (.*//g' -e "s.^.http://.g" -e "s/$/:${i}/g"|${ipsorter} >> ${thrdprty}/PeepingTom.txt
    cat *.gnmap|grep " ${i}/open/tcp//https/\| ${i}/open/tcp//https-alt/\| ${i}/open/tcp//https?/\| ${i}/open/tcp//ssl|http/"|\
                sed -e 's/Host: //g' -e 's/ (.*//g' -e "s.^.https://.g" -e "s/$/:${i}/g"|${ipsorter} >> ${thrdprty}/PeepingTom.txt
  done

  # Remove Empty Files
  func_title
  echo '[*] Removing Empty Files...'
  find ${parsedir} -size 0b -exec rm {} \;
  find ${parsedir} -size 1c -exec rm {} \;

  # Show Complete Message
  func_title
  echo '[*] Parsing Complete.'
  echo
}

# Start Statement
func_title
case ${1} in
  -g|--gather)
    func_gather
    ;;
  -h|--heuristic)
    func_heuristic
    ;;
  -p|--parse)
    func_parse
    ;;
  *)
    echo ' [Usage]...: ./Gnmap-Parser.sh [OPTION]'
    echo ' [Options].:'
    echo '             -g | --gather    = Gather .gnmap Files'
    echo '             -h | --heuristic = Heuristically Gather .gnmap Files'
    echo '             -p | --parse     = Parse .gnmap Files'
    echo
esac
