docker build -t squid_basic --build-arg auth=basic .
docker run -dt --name squid_basic -p 3128:3128 --rm squid_basic

docker build -t squid_digest --build-arg auth=digest .
docker run -dt --name squid_digest -p 3129:3129 --rm squid_digest
