#!/bin/bash

echo "Choose the Enumeration method:"
echo "1) for ICMP Protocol Enumerate"
echo "2) for ARP Protocol Enumerate"
echo "3) for Both ICMP and ARP Protocol Enumerate with port scanning"
echo "4) for DNS Reconnaissance"
echo "5) for TCPDUMP Traffic Analysis on ICMP and ARP Protocol Enumerate"
echo "6) for Exit"
echo "Type your choice:"
read -r choice

case $choice in
    1)
        enumerate_icmp_ping  # Execute the main function to perform the enumeration
        # Output statistics once the enumeration is complete
        echo "-- -- -- STATISTICS -- -- --"
        echo "Total Hosts Checked: $total_hosts_icmp"
        echo "Detected by ICMP: $icmp_detected"
        echo "Not Responding: $not_responding_icmp"
        ;;
    2)
        enumerate_arp  # Execute the main function of ARP to perform the enumeration
        # Output statistics once the enumeration is complete
        echo "-- -- -- STATISTICS -- -- --"
        echo "Total Hosts Checked: $total_hosts_arp"
        echo "Detected by ARP: $arp_detected"
        echo "Not Responding: $not_responding_arp"
        ;;
    3)
        enumerate_icmp_arp  # Execute the main function of both ICMP and ARP to perform enumeration
        # Output statistics once the enumeration is complete
        echo "-- -- -- STATISTICS -- -- --"
        echo "Total Hosts Checked: $total_hosts"
        echo "Detected by ICMP: $icmp_detected"
        echo "Detected by ARP: $arp_detected"
        echo "Not Responding for ICMP: $not_responding_icmp"
        echo "Not Responding for ARP: $not_responding_arp"
        ;;
    4)
        enumerate_ports "$current_ip"  # Execute the main function of both ICMP and ARP to perform enumeration
        ;;
    5)
        perform_dns_reconnaissance  # Execute the DNS Reconnaissance
        ;;
    6)
        tcpdump_capture_remove
        tcpdump_capture_start
        enumerate_icmp_ping
        enumerate_arp
        tcpdump_capture stop
        ;;
    7)
        echo "Exiting the Program"
        exit 0  # Exit the script
        ;;
    *)
        echo "Invalid choice!"
        exit 1
        ;;
esac

> enumeration_results.txt

# Function to convert IP address to an integer
ipaddr_to_int() {
    local ip="$1"  # Store the IP address passed to the function
    local a b c d  # Variable to store each octet of the IP address
    IFS=. read -r a b c d <<< "$ip"  # Split the IP into its individual octets
    # Return the integer representation of the IP address
    echo "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}

# Function to convert an integer representation of the IP address
int_to_ipaddr() {
    local num=$1  # Store the integer passed to the function
    # Return the IP address representation of the integer
    echo "$((num >> 24 & 255)).$((num >> 16 & 255)).$((num >> 8 & 255)).$((num & 255))"
}

# Prompt user for the starting IP
echo "Enter the start IP:"
read -r start_ip
echo "Enter the end IP:"
read -r end_ip

# Bandwidth Throttling: Maintaining a Maximum Transfer Rate of 0.3KB/s

PACKET_SIZE=1028  # Total size of an ICMP packet including headers in bytes (1000 bytes of payload + 8 bytes ICMP header + 20 bytes IP header)
BANDWIDTH_LIMIT=300  # 1KB/s limit in bytes

# Variables to track sent bytes and start time
bytes_sent=0
start_time=$(date +%s)

# Function to calculate how long to sleep to limit bandwidth
calculate_sleep() {
    local current_time=$(date +%s)  # Capture the current time in seconds to limit bandwidth
    # Calculate the elapsed time since the start of the script
    local elapsed_time=$(awk "BEGIN {print $current_time - $start_time}")
    # Calculate the expected time that should have elapsed based on the number of bytes sent and the bandwidth limit
    local expected_time=$(awk "BEGIN {print $bytes_sent / $BANDWIDTH_LIMIT}")

    # If the actual elapsed time is less than the expected time (meaning data is being sent too quickly)
    # calculate how long to sleep to adjust for difference
    if ((elapsed_time < expected_time)); then
        local sleep_time=$(awk "BEGIN {print $expected_time - $elapsed_time}")
        sleep $sleep_time
        echo "Sleeping for $sleep_time seconds"
    else
        echo "Not sleeping"
    fi
}


# Main function to iterate over the range of IPs and perform the ICMP ping method enumeration

enumerate_icmp_ping() {
    local start_int end_int ip_int current_ip  # Declare local variables
    start_int=$(ipaddr_to_int "$start_ip")  # Convert the start IP address to its integer representation
    end_int=$(ipaddr_to_int "$end_ip")  # Convert the end IP address to its integer representation

    # Loop through each integer value in the IP address range
    for ((ip_int=start_int; ip_int<=end_int; ip_int++)); do
        current_ip=$(int_to_ipaddr "$ip_int")  # Convert the integer back to its IP representation

        # Execute the ping command with specified parameters and store the result in the variable ping_result
        ping_result=$(ping -c 1 -s 1000 -W 1 "$current_ip")
        bytes_sent=$((bytes_sent + (PACKET_SIZE * 2)))  # Update the bytes sent with size of the ICMP packet times the number of pings (+c 2)
        calculate_sleep  # Call the function to calculate how long to sleep

        # Check if the ping response contains "bytes from", which indicates a successful response
        if echo "$ping_result" | grep -q "bytes from"; then
            # If the host response the following message will pop up
            echo "[ICMP - ACTIVE HOST] HOST $current_ip STATUS: UP AND DETECTED BY ICMP USING PING" | tee -a enumeration_results.txt
            icmp_detected=$((icmp_detected + 1))  # Increment the ICMP Detection variable by 1

            # Extract the number of packets transmitted, received and loss from the ping result and
            # store them in their given variable result
            packets_transmitted=$(echo "$ping_result" | grep "packets transmitted" | awk '{print $1}')
            packets_received=$(echo "$ping_result" | grep "packets transmitted" | awk '{print $4}')
            packets_loss=$(echo "$ping_result" | grep "packet loss" | awk '{print $6}')

            # Display the information
            echo "Packet Sent: $packets_transmitted"
            echo "Packet Received: $packets_received"
            echo "Packet Loss: $packets_loss"
        else
            # If both ping fail, output that the host is DOWN or not responding
            echo "[ICMP - UNACTIVE HOST] HOST $current_ip STATUS: DOWN OR NOT RESPONDING TO ICMP" | tee -a enumeration_results.txt
            not_responding_icmp=$((not_responding_icmp + 1))  # Increment the not responding variable by 1
        fi
    done
}


# Main function to iterate over the range of IPs and perform the ARP method enumeration

enumerate_arp() {
    local start_int end_int ip_int current_ip arping_result mac_address  # Declare local variables
    start_int=$(ipaddr_to_int "$start_ip")  # Convert the start IP address to its integer representation
    end_int=$(ipaddr_to_int "$end_ip")  # Convert the end IP address to its integer representation

    # Loop through each integer value in the IP address range
    for ((ip_int=start_int; ip_int<=end_int; ip_int++)); do
        current_ip=$(int_to_ipaddr "$ip_int")  # Convert the integer back to its IP representation

        # Use the arping command to query the ARP cache for the current_ip and if the IP is not found or any error occurs,
        # the output will be discarded to avoid unwanted error messages
        arping_result=$(sudo arping -c 1 "$current_ip" 2>&1)

        # The subsequent block checks the result of the arping command
        if [ $? -eq 0 ]; then
            # If the above checks are passed, the MAC address of the device with the given IP is extracted
            mac_address=$(echo "$arping_result" | grep "bytes from" | awk '{print $4}')
            # If the conditions met, then it will show a message saying the host is up and detected by ARP, with its MAC address
            echo "[ARP - ACTIVE HOST] HOST $current_ip STATUS: UP AND DETECTED BY ARP WITH MAC: $mac_address" | tee -a enumeration_results.txt
            arp_detected=$((arp_detected + 1))  # Increment arp detection variable by 1
        else
            # If it does not met, then it will display a message saying host did not respond to ARP
            echo "[ARP - UNACTIVE HOST] HOST $current_ip DID NOT RESPOND TO ARP" | tee -a enumeration_results.txt
            not_responding_arp=$((not_responding_arp + 1))  # Increment the not responding variable by 1
        fi
    done
}


# This function combines ICMP and ARP scanning. It first checks if hosts are active using ICMP ping.
# If a host is active, it then performs an ARP scan on that host.

enumerate_icmp_arp() {
    local start_int end_int ip_int current_ip arping_result mac_address ping_result  # Declare local variables
    start_int=$(ipaddr_to_int "$start_ip")  # Convert the start IP address to its integer representation
    end_int=$(ipaddr_to_int "$end_ip")  # Convert the end IP address to its integer representation

    # Convert the user-supplied start and end IPs to their integer equivalents for easier iteration.
    start_int=$(ipaddr_to_int "$start_ip")
    end_int=$(ipaddr_to_int "$end_ip")

    # Loop through each integer value in the IP address range
    for ((ip_int=start_int; ip_int<=end_int; ip_int++)); do
        current_ip=$(int_to_ipaddr "$ip_int")  # Convert the integer back to its IP representation

        # Execute the ping command with specified parameters and store the result in the variable ping_result
        ping_result=$(ping -c 1 -s 1000 -W 1 "$current_ip")
        bytes_sent=$((bytes_sent + (PACKET_SIZE * 2)))  # Update the bytes sent with size of the ICMP packet times the number of pings (+c 2)
        calculate_sleep  # Call the function to calculate how long to sleep

        # Check if the ping response contains "bytes from", which indicates a successful response
        if echo "$ping_result" | grep -q "bytes from"; then
            # If the host response the following message will pop up
            echo "[ICMP - ACTIVE HOST] HOST $current_ip STATUS: UP AND DETECTED BY ICMP USING PING" | tee -a enumeration_results.txt
            icmp_detected=$((icmp_detected + 1))  # Increment the ICMP Detection variable by 1

            # Extract the number of packets transmitted, received and loss from the ping result and
            # store them in their given variable result
            packets_transmitted=$(echo "$ping_result" | grep "packets transmitted" | awk '{print $1}')
            packets_received=$(echo "$ping_result" | grep "packets transmitted" | awk '{print $4}')
            packets_loss=$(echo "$ping_result" | grep "packet loss" | awk '{print $6}')

            # Display the information
            echo "Packet Sent: $packets_transmitted"
            echo "Packet Received: $packets_received"
            echo "Packet Loss: $packets_loss"

            # If the ping command was successful, perform the ARP scan.
            arping_result=$(sudo arping -c 1 "$current_ip" 2>&1)
            if [ $? -eq 0 ]; then
                mac_address=$(echo "$arping_result" | grep "bytes from" | awk '{print $4}')
                echo "[ARP - ACTIVE HOST] HOST $current_ip STATUS: UP AND DETECTED BY ARP WITH MAC: $mac_address" | tee -a enumeration_results.txt
                arp_detected=$((arp_detected + 1))
            else
                echo "[ARP - UNREACHABLE HOST] HOST $current_ip DID NOT RESPOND TO ARP" | tee -a enumeration_results.txt
                not_responding_arp=$((not_responding_arp + 1))
            fi
        else
            echo "[ICMP - INACTIVE HOST] HOST $current_ip STATUS: DOWN OR NOT RESPONDING TO ICMP" | tee -a enumeration_results.txt
            not_responding_icmp=$((not_responding_icmp + 1))
        fi
    done
}


# This function is designed to enumerate these 5 well-known ports from the result of ICMP and ARP enumeration

enumerate_ports() {
    local start_int end_int ip_int current_ip open_ports  # Declare local variables
    start_int=$(ipaddr_to_int "$start_ip")  # Convert the start IP address to its integer representation
    end_int=$(ipaddr_to_int "$end_ip")  # Convert the end IP address to its integer representation

    # Loop through each integer value in the IP address range
    for ((ip_int=start_int; ip_int<=end_int; ip_int++)); do
        current_ip=$(int_to_ipaddr "$ip_int")  # Convert the integer back to its IP representation
        echo "SCANNING $current_ip FOR OPEN PORTS: FTP, SSH, Telnet, SMTP and HTTP ..."  # Print a message

        # Run the nmap tool to scan the specified ports of the IP address
        # Then use the grep to filter out the line that has the word (open). This will give the list of open ports.
        open_ports=$(nmap -p 21,22,23,25,80 "$current_ip" | grep open)

        # Check if the open_ports variable is empty
        if [[ -z "$open_ports" ]]; then
            echo "[NO OPEN PORT] NO OPEN PORTS (FTP, SSH, Telnet, SMTP and HTTP ) DETECTED FOR $current_ip" | tee -a enumeration_results.txt
        else
            while IFS= read -r line; do  # Begin a loop to read each line from the variable open_ports
                # For each line in open_ports, print the line to the console and append to the file enumeration_results.txt
                echo "[OPEN PORT] OPEN PORTS DETECTED FOR $current_ip: $line" | tee -a enumeration_results.txt
            done <<< "$open_ports"  # The triple less-than sign indicates that the loop should read from the open variable
        fi
    done
}


# Function to perform DNS reconnaissance on a range of IP addresses

perform_dns_reconnaissance() {
    local start_int end_int ip_int current_ip domain_name dns_server  # Declare local variables
    start_int=$(ipaddr_to_int "$start_ip")  # Convert the start IP address to its integer representation
    end_int=$(ipaddr_to_int "$end_ip")  # Convert the end IP address to its integer representation

    # Loop through each integer value in the IP address range
    for ((ip_int=start_int; ip_int<=end_int; ip_int++)); do
        current_ip=$(int_to_ipaddr "$ip_int")  # Convert the integer back to its IP representation

        # Use nslookup to retrieve the domain name associated with the IP address
        domain_name=$(nslookup "$current_ip" | grep "name =" | awk '{print $4}' | sed 's/\.$//')
        # Check if a domain name was found for IP
        if [ -z "$domain_name" ]; then
            echo "[DNS - DOMAIN NOT FOUND] No domain found for IP $current_ip" | tee -a enumeration_results.txt
            continue
        fi
        echo "[DNS - DOMAIN FOUND] Found domain $domain_name for IP $current_ip" | tee -a enumeration_results.txt

        # Use dnsrecon for DNS reconnaissance on the found domain name
        echo "Performing DNS Recon using dnsrecon for $domain_name"
        dnsrecon -d "$domain_name" -t std,axfr
    done
}


# Perform Analysis of how much traffic has been generated by the script

# Set the path for the capture file where tcpdump will save the packet data.
CAPTURE_FILE="/home/kali/Documents/enumeration_capture.pcap"
# This is a placeholder for the network interface variable.
NETWORK_INTERFACE="eth0"
# Initialize a variable to store the Process ID of tcpdump, which is currently empty.
TCPDUMP_PID=""

# Define a function to remove the capture file if it exists.
tcpdump_capture_remove() {
  # Check if the capture file exists.
  if [ -f "$CAPTURE_FILE" ]; then
    # Use sudo to remove the capture file forcefully without prompting for confirmation.
    sudo rm -f "$CAPTURE_FILE"
  fi
}

# Define a function to control the capturing of tcpdump.
tcpdump_capture() {
  # Local action
  local action=$1
  # The first input argument to the function is the action to take (start or stop).
  case $action in
    start)
      # Start tcpdump to start capturing packets.
      echo "Starting tcpdump..."
      # Run tcpdump in the background
      sudo tcpdump -i $NETWORK_INTERFACE -w $CAPTURE_FILE &
      # Get the Process ID (PID) of the tcpdump command just run.
      TCPDUMP_PID=$!
      # Display a message indicating tcpdump has started and display its PID.
      echo "Started tcpdump with PID $TCPDUMP_PID"
      ;;
    stop)
      # The action is to stop capturing packets.
      echo "Stopping tcpdump..."
      # Display a message that the script will now analyze the traffic generated.
      echo "Analysis of Traffic Generated by the script."
      # Send a SIGTERM to the tcpdump process to stop it.
      sudo kill -SIGTERM $TCPDUMP_PID
      # Remove the capture file
      tcpdump_capture_remove
      # Process the captured data to calculate the total packets and bytes.
      BEGIN { FS="\t"; } # Set Output Field Separator as tab for pretty printing
      {
        total_packets = 0;
        total_bytes = 0;
        first_packet = 1;
        previous_time = 0;
      }
      # For each line processed, increment the total_packets count.
      {
        total_packets++;
        # Increment the total_bytes by the byte length of the packet.
        # The byte length is assumed to be the last field in the tcpdump output.
        match($0, /length ([0-9]+)/, arr);
        total_bytes += arr[1];
        if(first_packet) {
          first_packet = 0;
        } else {
          current_time = $1; # Assuming the first field is the timestamp
          delay = current_time - previous_time; # Calculate delay
          print "Delay between packets (seconds):", delay;
        }
        previous_time = current_time; # Update previous_time for next iteration
      }
      END {
        # Print the total packets captured and total bytes.
        print "Total packets captured:", total_packets;
        print "Total bytes captured:", total_bytes;
        # If at least one packet was captured, calculate and print the average packet size.
        if (total_packets > 0) {
          print "Average packet size (bytes):", (total_bytes/total_packets);
        }
      }
      ;;
  esac
}

