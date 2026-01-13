#Testing 
 # - get the ip a of the computer 
 # - nmap -sT(tcp connect scan) -p( which ports) ip address 


import socket
import csv
import sys # access to command line arguments

if len(sys.argv) < 2:
    print("Usage: python3 scanner.py <target_ip> [start-end]")
    sys.exit(1)

target_ip = sys.argv[1]

# sys = ["scanner.py", "127.0.0.1"]

start_port = 1
end_port = 1024

if len(sys.argv) >= 3:
    port_range = sys.argv[2]

    try:
        start_port, end_port = port_range.split("-")
        start_port = int(start_port)
        end_port = int(end_port)
    except:
        print("Invalid port range format. Use: start-end")
        sys.exit(1) #stops the program safely

target_ip = sys.argv[1]


ports_to_scan = range(start_port, end_port + 1)


common_services = {
    22: "SSH",
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS"
}

risky_services = {
    "TELNET": "HIGH",
    "FTP": "MEDIUM",
    "HTTP": "LOW",
    "SSH": "LOW"
}


risk_scores = {
     "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

total_risk_score = 0

scan_results =[]


for port in ports_to_scan:
        
        # Calling the socket constructor
        # Saying you want to use TCP connection and want to use IPv4

        #socket object
        s = socket.socket(socket.AF_INET ,socket.SOCK_STREAM )

        # creating a timeout as it can try to conenct to a closed port

        s.settimeout(3)

        ## attempt to connect to the target
        result = s.connect_ex((target_ip , port))

        if result == 0 :
 
            service = common_services.get(port , "UNKNOWN ")
           
            scan_results.append({
                "port":  port,
                "service": service,
                "status": "OPEN"
            })

            print(f" port {port} is open -> {service}")

            if service in risky_services:
                print(f"Risk : {risky_services[service]}")

                if "HIGH" in risky_services :
                    total_risk_score += risk_scores["HIGH"]
                
                if "MEDIUM" in risky_services:
                    total_risk_score += risk_scores["MEDIUM"]
                
                if "LOW" in risky_services:
                    total_risk_score += risk_scores["LOW"]


            if port == 22:
            
                try:
                    banner = s.recv(1024) #read up to 1024 bytes from the service 
                    print(f"Banner: {banner.decode().strip()}")

                except:
                    print("Banner: Not Received")
            #HTTP header grabbing 
            if port == 80:
                try:
                    http_request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    s.send(http_request.encode())

                    response = s.recv(1024)
                    headers = response.decode(errors="ignore").split("\r\n")

                    print("HTTP Headers:")
                    for header in headers:
                        if header:
                            print(header)
                except:
                    print("Could not retrieve HTTP headers")
        
        else:

            scan_results.append({
                "port": port,
                "service": "N/A",
                "status": "CLOSED"
            })
            print(f" port {port} is closed")

        s.close()


print("\n Scan Results")

for result in scan_results:
    print(f"port {result['port']} |Status: {result['status']}  | Service: {result['service']}")

print("\n--- Overall Risk Assessment ---")

if total_risk_score >= 6:
    print("Overall Risk Level: HIGH")
elif total_risk_score >= 3:
    print("Overall Risk Level: MEDIUM")
else:
    print("Overall Risk Level: LOW")


#writing to a csv file

with open("scan_report.csv", mode = "w" , newline="") as file:
    writer = csv.writer(file)

    writer.writerow(["Port" , "Status" , "Service"])

    for result in scan_results:
        writer.writerow([
            result["port"],
            result["status"],
            result["service"]
        ])