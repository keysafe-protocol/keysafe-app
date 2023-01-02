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
  docker pull mysql:latest 
  docker run --name ks-db -p 12345:3306 -v $PWD/data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=ks123 -d mysql:latest
```
+ login mysql docker instance to setup db 
```
  docker exec -it ks-db bash
  # inside docker, create db, user and schema
  mysql -h localhost -u root -pks123
  copy app/schema.sql to mysql shell
  exit # mysql shell
  exit # mysql docker instance
```
+ build keysafe-app docker instance
```
  git clone https://github.com/keysafe-protocol/keysafe-app.git
  cd keysafe-app
  git checkout polkadot
  cd docker
  docker build -t ks01 -f Dockerfile .
  cd ..
  docker run --network host -v ${PWD}:/root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app -ti ks01
```
+ inside docker instance, build package
```
  bash /root/get_ks_sgx.sh
  cd /root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app/;
  make -f MakeHwFile SGX_MODE=SW 
```
+ inside docker instance, run unit test
```
  cd /root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app/app; cargo test
```
+ inside docker instance, prepare environment before start up
```
  cd /root/incubator-teaclave-sgx-sdk/samplecode/keysafe-app/bin;
  ../scripts/prepare_bin.sh
```
+ start service, once started, ./app stucks waiting for requests
```
  export KS_ACCOUNT="zone envelope fish dolphin cup conduct burden tomato uphold final wood dune"
  ./app &
```
+ start front-end 
```
  cd <a-new-directory>
  git clone https://github.com/keysafe-protocol/keysafe-front
  git checkout polkadot
  docker build -t keysafe-frontend .
  docker run --rm -p 3000:3000 -e REACT_APP_BASE_URL='https://<your-ip-address>:30000/ks' keysafe-frontend
```
+ visit http://<your-ip-address>:3000 to open the website
