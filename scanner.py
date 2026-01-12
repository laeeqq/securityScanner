import socket

target_ip = "127.0.0.1"
ports_to_scan = [22,80,443] 

common_services = {
    22: "SSH",
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS"
}


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
            print(f" port {port} is open -> {service}")

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


            print(f" port {port} is closed")

        s.close()