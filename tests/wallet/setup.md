#build docker
./docker_build.sh

#get shell in docker
./docker_start.sh


#init token in docker shell (it should be plugged in)
service pcscd restart
python3 tools/pico-hsm-tool.py --pin 648219 initialize --so-pin 57621880


#run and validate ETH compatible signature
./tests/wallet/secp256k1.sh 
