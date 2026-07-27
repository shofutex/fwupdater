#!/bin/bash

#This VULTR API key is for a user who can only edit the firewall
VULTR_API_KEY=<key>

myipv6=$(curl -s https://v6.ipinfo.io/?token=<key> | jq ".ip" | sed -e 's/\"//g')
myipv4=$(curl -s https://ipinfo.io/?token=<key> | jq ".ip" | sed -e 's/\"//g')

#mysubnet="$(echo $myipv6 | sed -e 's/:/ /g' | awk '{ print $1 $2 $3 $4 }' | sed -e 's/ /:/g')::"
mysubnet6="$(echo $myipv6 | sed -e 's/:/ /g' | awk '{ print $1,$2,$3,$4 }' | sed -e 's/\"//g' | sed -e 's/ /:/g')::"

myIDS=$(curl -s "https://api.vultr.com/v2/firewalls"   -X GET   -H "Authorization: Bearer ${VULTR_API_KEY}" | jq ".firewall_groups[].id" | sed -e 's/\"//g')
rules=()
for I in $myIDS; do
    mydata=$(curl -s "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X GET \
  -H "Authorization: Bearer ${VULTR_API_KEY}")
    rules+=( $(echo $mydata | jq ".firewall_rules[] | select(.notes==\"framework\") | {id, subnet, subnet_size, port} | .rule_id = \"$I\"" | tr -d '\n' | sed -e 's/\s\+/\&/g') )

done

rulelen=${#rules[@]}

extra_rules=0
good_rules=0
old_ips=()

for rule in ${rules[@]}; do
    #echo $rule | sed -e 's/\&/ /g' | jq "select(.subnet==\"$mysubnet6\" or .subnet==\"$myipv4\")" 
    if [ $(echo $rule | sed -e 's/\&/ /g' | jq "select(.subnet!=\"$mysubnet6\" and .subnet!=\"$myipv4\")" | wc -l) -gt 0 ]; then
        extra_rules=1
    elif [ $(echo $rule | sed -e 's/\&/ /g' | jq "select(.subnet==\"$mysubnet6\" or .subnet==\"$myipv4\")" | wc -l) -gt 0 ]; then
        good_rules=1
    fi
done

echo ${#rules[@]} $extra_rules

if [ $good_rules -eq 0 ]; then
    echo "Adding new rules for this IP"
    for I in $myIDS; do

        if [ "$mysubnet6" != "::" ]; then
        curl "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X POST \
  -H "Authorization: Bearer ${VULTR_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{
    "ip_type" : "v6",
    "protocol" : "tcp",
    "port" : "443",
    "subnet" : "'$mysubnet6'",
    "subnet_size" : 64,
    "source" : "",
    "notes" : "framework"
  }'
        curl "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X POST \
  -H "Authorization: Bearer ${VULTR_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{
    "ip_type" : "v6",
    "protocol" : "tcp",
    "port" : "22",
    "subnet" : "'$mysubnet6'",
    "subnet_size" : 64,
    "source" : "",
    "notes" : "framework"
  }'
        fi
        curl "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X POST \
  -H "Authorization: Bearer ${VULTR_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{
    "ip_type" : "v4",
    "protocol" : "tcp",
    "port" : "443",
    "subnet" : "'$myipv4'",
    "subnet_size" : 32,
    "source" : "",
    "notes" : "framework"
  }'
        curl "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X POST \
  -H "Authorization: Bearer ${VULTR_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{
    "ip_type" : "v4",
    "protocol" : "tcp",
    "port" : "22",
    "subnet" : "'$myipv4'",
    "subnet_size" : 32,
    "source" : "",
    "notes" : "framework"
  }'
    done
fi
if [ $extra_rules -gt 0 ]; then
    echo "Deleting extras"

    for I in $myIDS; do
        isdone=0
        while [ $isdone -eq 0 ]; do

            mydata=$(curl -s "https://api.vultr.com/v2/firewalls/$I/rules" \
  -X GET \
  -H "Authorization: Bearer ${VULTR_API_KEY}")

            myrule_id=$(echo $mydata | jq ".firewall_rules[] | select(.notes==\"framework\") | select(.subnet !=\"$mysubnet6\" and .subnet !=\"$myipv4\").id" | head -n1)
            if [ "$myrule_id" != "" ]; then
                curl "https://api.vultr.com/v2/firewalls/$I/rules/$myrule_id" \
  -X DELETE \
  -H "Authorization: Bearer ${VULTR_API_KEY}"
                else
                    isdone=1
            fi


        done
    done
fi

echo Pending Vultr processing request...
sleep 120
echo Complete
