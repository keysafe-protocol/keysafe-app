# keysafe-sgx
# requirements
## linux-sgx
+ follow https://github.com/intel/linux-sgx#build-and-install-the-intelr-sgx-driver
+ install linux-sgx
+ keysafe relies on intel-sgx to seal the shards of user secrets
## baidu-rust-sgx-sdk
+ follow https://github.com/apache/incubator-teaclave-sgx-sdk
+ to install sgx-sdk
## mysql database
+ install mysql-server 
+ create a database, then import schema.sql into your database
## enterprise email account
+ you will need an email account to send notification mail to users when they register
# build
+ download baidu sgx-sdk with the name incubator-teaclave-sgx-sdk
+ copy the code into incubator-teaclave-sgx-sdk/samplecode
+ change Makefile SGX_SDK and TOP_DIR according to your environment
+ make SGX_MODE=SW
# build with ks-sgx
+ clone ks-sgx in another directory,
+ cd ks-sgx; make
+ go back to keysafe-sgx
+ change Makefile MakeHwFile.
+ SGX_SDK and TOP_DIR according to your environment
+ KS_SGX_SRC point to ks-sgx directory.
+ make -f MakeHwFile
# execute
+ cd bin
+ ln -s ../certs .
+ ./app
# test
+ download postman
+ click "My Workspace", "New", "Websocket Request (Beta)"
+ connect to "wss://127.0.0.1:12345/save"
+ use postman as a web front-end to communicate with enclave.
