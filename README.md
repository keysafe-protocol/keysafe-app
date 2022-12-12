# dev environment setup and build guide
## setup without docker
### install sgx-rust-sdk
+ https://github.com/intel/linux-sgx#build-and-install-the-intelr-sgx-driver
### install linux-sgx 
+ https://github.com/intel/linux-sgx#introduction
### install sgx-ssl
+ https://github.com/intel/intel-sgx-ssl
### build
+ cd <sgx-rust-sdk>/samplecode
+ git clone https://github.com/keysafe-protocol/keysafe-app.git
+ set environment:
  + SGX_SDK_RUST 
  + SGX_SDK
  + SGX_MODE # set to SW if you don't have SGX support
  + SGXSSL_CRYPTO
### unit test
```
   cd app
   cargo test
```
### build ks-sgx
```
  git clone https://github.com/keysafe-protocol/keysafe-sgx
  cd ks-sgx; make
```
### build webapp with sgx
```
  cd keysafe-app; make
```
### execute
```
  cd bin
  ln -s ../certs .
  ./app
```
## setup with docker
+ install docker
+ build mysql db docker instance 
```
  git clone https://github.com/keysafe-protocol/keysafe-app.git
  docker pull mysql:latest 
  docker run --name ks-db -p 12345:3306 -v $PWD/data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=ks123 -d mysql:latest
```
+ login mysql docker instance to setup db 
```
  docker exec -it ks-db bash
  # inside docker, create db, 
```
+ build keysafe-app docker instance
```
  cd docker
  docker build -t ks01 -f Dockerfile .
  cd ..
  docker run -v ${PWD}:/root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app -ti ks01
```
+ inside docker instance, run unit test
```
  cd incubator-teaclave-sgx-sdk/samplecode/keysafe-app/app; cargo test
```
+ inside docker instance, build package
```
  cd /root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app/;
  make SGX_MODE=SW
```
+ inside docker instance, prepare environment before start up
```
  cd bin
  ../scripts/prepare_bin.sh
```
