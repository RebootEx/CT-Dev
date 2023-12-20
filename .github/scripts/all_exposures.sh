#!/usr/bin/env bash
#-------------------------------------------------------#
# Time
START_TIME=$(date +%s)
#-------------------------------------------------------#
#A bit of Styling
RED='\033[31m'
GREEN='\033[32m'
DGREEN='\033[38;5;28m'
GREY='\033[37m'
BLUE='\033[34m'
YELLOW='\033[33m'
PURPLE='\033[35m'
PINK='\033[38;5;206m'
VIOLET='\033[0;35m'
RESET='\033[0m'
NC='\033[0m'
#-------------------------------------------------------#
# For debug
# set -x
#-------------------------------------------------------#

#-------------------------------------------------------#
#Sanity Checks
if [ -z "$LOONIX_TG_BOT" ] && [ -z "$LOONIX_TOPIC_ID" ]; then
    echo "\nError: TG bot token or topic id is empty"
    echo "[+]TG Bot Token: $LOONIX_TG_BOT"
    echo "[+]TG Bot TopicID: $LOONIX_TOPIC_ID"
 exit 1   
fi
#-------------------------------------------------------#



#----------------------------------------------------------------------------#
#Debloat
 bash <(curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Arsenal/main/misc/Github/Runners/Ubuntu/debloat.sh") 2>/dev/null
#----------------------------------------------------------------------------#
#Install Coreutils
 sudo apt update -y
 sudo apt install coreutils curl dos2unix jq moreutils wget -y
 pip install ansi2txt
# Do again, sometimes fails
 sudo apt install coreutils curl dos2unix jq moreutils wget -y
 pip install ansi2txt         
# For TG BOT Notifs
 pip install apprise 
 pip install apprise 2>/dev/null
# For neofetch
 pip install archey4
 pip install archey4 2>/dev/null
#-------------------------------------------# 
#Install Addons
# eget for bins
  sudo curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/eget" -o "/usr/local/bin/eget" && sudo chmod +xwr "/usr/local/bin/eget"
 #7z
  sudo rm /usr/bin/7z 2>/dev/null ; sudo rm /usr/local/bin/7z 2>/dev/null
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/7z" --to "/usr/local/bin/7z"
 #anew
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/anew" --to "/usr/local/bin/anew"
 #Cent
  sudo curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/cent" -o "/usr/local/bin/cent" && sudo chmod +xwr "/usr/local/bin/cent"
 #Httpx
  sudo curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/httpx" -o "/usr/local/bin/httpx" && sudo chmod +xwr "/usr/local/bin/httpx"
 #Inscope
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/inscope" --to "/usr/local/bin/inscope" 
 #Interactsh
  sudo curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/interactsh-client" -o "/usr/local/bin/interactsh-client" && sudo chmod +xwr "/usr/local/bin/interactsh-client"
 #Nuclei
  sudo curl -qfsSL "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/nuclei" -o "/usr/local/bin/nuclei" && sudo chmod +xwr "/usr/local/bin/nuclei"
 #ScopeView
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/scopeview" --to "/usr/local/bin/scopeview"
 #Tok
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/tok" --to "/usr/local/bin/tok"
 #YQ 
  sudo eget "https://raw.githubusercontent.com/Azathothas/Toolpacks/main/x86_64/yq" --to "/usr/local/bin/yq" 
#----------------------------------------------------------------------------#

#----------------------------------------------------------------------------#
# Make sure we have enough baseline data
#Quick Sanity Check
curl -qfsSL "https://raw.githubusercontent.com/RebootEx/CertStream-Bangladesh/main/Data/bd_ccTLDs/certstream_domains_bd_all_24h_httpx.txt" | awk '{print $1}' | grep -i 'http' | sort -u -o "/tmp/bd_24h.txt"
 if [ $(wc -l < "/tmp/bd_24h.txt") -le 10 ]; then
    echo "Total Targets to Scan is way too little"
    exit 1
 else
    TOTAL_HOSTS="$(wc -l < /tmp/bd_24h.txt)" && export TOTAL_HOSTS="$TOTAL_HOSTS"
    echo "Total Domains: $TOTAL_HOSTS"
 fi
#Update Nuclei & Templates
 sudo nuclei -update
 #Templates: /root/nuclei-templates || $HOME/nuclei-templates
 sudo nuclei -update-templates ; nuclei -update-templates 2>/dev/null
#Get Resolvers
 curl -qfsSL "https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.ipv6" -o "/tmp/resolvers.txt"
 curl -qfsSL "https://raw.githubusercontent.com/edoardottt/secfiles/main/dns/trusted-resolvers-small.txt" | anew -q "/tmp/resolvers.txt"
 curl -qfsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" | anew -q "/tmp/resolvers.txt"
 sort -u "/tmp/resolvers.txt" -o "/tmp/resolvers.txt"
# #Get Templates
#  cent init
#  cent --path "$HOME/cent-nuclei-templates" --threads 20
#Run (needs sudo for Reasons Unknown)
#Scans ~ 1000 Hosts (1000 Templates) ~ 100-120 Mins  
#https://github.com/projectdiscovery/nuclei-templates
#Default
 timeout -k 1m 250m sudo nuclei -list "/tmp/bd_24h.txt" -templates "/root/nuclei-templates" -resolvers "/tmp/resolvers.txt" -tags "disclosure,env,exposure" -exclude-severity "info,low,medium,unknown" -exclude-tags "git" -exclude-id "custom-splunk-info-disclose-detect,custom-datapump-source-code-detect" -headless -disable-redirects -concurrency 100 -rate-limit 200 -project -stats -o "/tmp/nuclei_out.txt" > "/tmp/nuclei_out.log" 2>&1
# # If using cent-templates
#  sudo nuclei -list "/tmp/bd_24h.txt" -templates "$HOME/cent-nuclei-templates" -resolvers "/tmp/resolvers.txt" -tags "disclosure,env,exposure" -exclude-severity "info,low,medium,unknown" -exclude-tags "git" -exclude-id "custom-splunk-info-disclose-detect,custom-datapump-source-code-detect" -headless -disable-redirects -concurrency 100 -rate-limit 200 -project -stats -o "/tmp/nuclei_out.txt" > "/tmp/nuclei_out.log" 2>&1
#View logs: tail -f "/tmp/nuclei_out.log"
#View Output: tail -f  "/tmp/nuclei_out.txt"
#Parse & Add
#Output
 sort -u "/tmp/nuclei_out.txt" -o "/tmp/Nuclei_Exposure.txt"
#Logs
 cat "/tmp/nuclei_out.log" | ansi2txt | tee "/tmp/Nuclei_Exposure.log"
#----------------------------------------------------------------------------#

#----------------------------------------------------------------------------#
# Time meth
END_TIME=$(date +%s)
ELAPSED_TIME=$((END_TIME - START_TIME))
ELAPSED_TIME_MINUTES=$((ELAPSED_TIME / 60))
ELAPSED_TIME_HOURS=$((ELAPSED_TIME / 3600))
START_TIME_BST=$(TZ="Asia/Dhaka" date -d "@$START_TIME" "+%Y-%m-%d %I:%M:%S %p BD TIME")
END_TIME_BST=$(TZ="Asia/Dhaka" date -d "@$END_TIME" "+%Y-%m-%d %I:%M:%S %p BD TIME")
# Create Body For TG_BOT
echo '```mathematica' > "/tmp/INVENTORY_TIME.md"
echo -e "Time Stats:" >> "/tmp/INVENTORY_TIME.md"
echo -e "Started At: $START_TIME_BST" >> "/tmp/INVENTORY_TIME.md"
echo -e "Finished At: $END_TIME_BST" >> "/tmp/INVENTORY_TIME.md"
echo -e "[Seconds: $ELAPSED_TIME]" >> "/tmp/INVENTORY_TIME.md"
echo -e "[Minutes: $ELAPSED_TIME_MINUTES]" >> "/tmp/INVENTORY_TIME.md"
echo -e "[Hours: $ELAPSED_TIME_HOURS]" >> "/tmp/INVENTORY_TIME.md"
echo '```' >> "/tmp/INVENTORY_TIME.md"
#----------------------------------------------------------------------------#

#----------------------------------------------------------------------------#
#TG-BOT
 echo -e "*Job* : ⚛️ Nuclei Scan Exposures & Info Disclosures 🪰 ➼ 🇧🇩 [bd_ccTLDs](https://github.com/RebootEx/CertStream-Bangladesh/blob/main/Data/bd_ccTLDs/certstream_domains_bd_all_24h.txt)" > "/tmp/INVENTORY_TG_BOT.md"
 echo -e "*Cluster* : Externa ⚝" >> "/tmp/INVENTORY_TG_BOT.md"
# HOST_IP | REGION
 HOST_IP="$(curl --ipv4 -qfskSL http://ipv4.whatismyip.akamai.com | sed 's/[[:space:]]*$//' )" && export HOST_IP="$HOST_IP"
 HOST_REGION="$(curl --ipv4 -qfskSL "http://ip-api.com/json/" | jq -r '"\(.country | gsub(" "; "-"))-\(.city | gsub(" "; "-"))"')" && export HOST_REGION="$HOST_REGION"
#Add bandwidth
 echo -e '\n```mathematica' >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "\n[+] Origin Traffic: $HOST_IP ($HOST_REGION)" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "\n[+] Bandwidth:\n" >> "/tmp/INVENTORY_TG_BOT.md"
 ip -s -h link show eth0 | grep -i "RX" -A 5 >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "\n[+] Nuclei Stats:\n" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "Total Domains Scanned: $TOTAL_HOSTS" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "Excluded Severity : info low medium unknown" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "Excluded Tags : git" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e "Max Runtime : Stops after 250 Minutes, may not Finish Scanning Everything. Check Logs" >> "/tmp/INVENTORY_TG_BOT.md"
 echo -e '```' >> "/tmp/INVENTORY_TG_BOT.md"
#Add Time
 echo -e "\n$(cat /tmp/INVENTORY_TIME.md)\n" >> "/tmp/INVENTORY_TG_BOT.md"
#Send Initial 
 apprise "tgram://$LOONIX_TG_BOT/?format=markdown" -vv -b "$(cat /tmp/INVENTORY_TG_BOT.md)" 
#Nuclei Stats
 echo -e '```bash' >> "/tmp/NUCLEI_STATS.md"
 echo -e "\n[+] Results:\n\n$(cat /tmp/Nuclei_Exposure.txt)\n" >> "/tmp/NUCLEI_STATS.md"
 echo -e '```' >> "/tmp/NUCLEI_STATS.md"
#Send nuclei
 apprise "tgram://$LOONIX_TG_BOT/?format=markdown" -vv -b "$(cat /tmp/NUCLEI_STATS.md)"
#Attachments
 SAFE_END_TIME_BST="$(echo $END_TIME_BST | sed 's/[ -]/_/g; s/:/_/g')"
 cp "/tmp/Nuclei_Exposure.log" "/tmp/Nuclei_Exposure_$SAFE_END_TIME_BST.log"
 cp "/tmp/Nuclei_Exposure.txt" "/tmp/Nuclei_Exposure_$SAFE_END_TIME_BST.txt"
#Send 
 apprise "tgram://$LOONIX_TG_BOT/?format=markdown" -vv -b "*Logs & Output*" --attach "/tmp/Nuclei_Exposure_$SAFE_END_TIME_BST.log" --attach "/tmp/Nuclei_Exposure_$SAFE_END_TIME_BST.txt"
#----------------------------------------------------------------------------#
