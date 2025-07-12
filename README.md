Ad Blocker at the DNS Request Level

This program functions by operating as the DNS server for clients of your choosing.
Each time a packet is received on port 53, it is assumed to be a DNS packet.
If the packet is a query, the program performs one of the following:
1. If the query is in the block list, create a DNS response with the localhost address as the answer and send to requestor
2. If the query is in not in the block list, forward the packet to the "true" gateway.
    - This is non-blocking - the corresponding response will be sent back to the client once it arrives
If the packet is a response, it will be forwarded to the original requestor.


To run:
IF USING UBUNTU, FOLLOW THE INSTRUCTIONS TO FREE UP PORT 53 ON THE HOST! https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html
1. edit .env.sample to your preferred values (most likely your default DNS server will be your home's gateway)
2. rename .env.sample to .env

install docker, and run "docker-compose up" in the directory this project lives in

Then change a devices DNS server address to your host's address and watch what happens!

alternatively, build the rust project from source and run the binary directly.