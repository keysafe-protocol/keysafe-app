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
+ build keysafe-app docker instance
```
  git clone https://github.com/keysafe-protocol/keysafe-app.git
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
  cd incubator-teaclave-sgx-sdk/samplecode/keysafe-app/;
  make SGX_MODE=SW
```
