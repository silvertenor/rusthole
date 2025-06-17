To run:

1. edit .env.sample to your preferred values (most likely your default DNS server will be your home's gateway)
2. rename .env.sample to .env

install docker, and run "docker-compose up" in the directory this project lives in

Then change a devices DNS server address to your host's address and watch what happens!

alternatively, build the rust project from source and run the binary directly.