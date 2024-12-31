.PHONY: build init run

build:
	cd .. &&  . ./edksetup.sh BaseTools && build -D SMM_REQUIRE
	cp ../Build/OvmfX64/DEBUG_GCC/FV/OVMF.fd ./

init:
	./init.sh

run: 
	./run.sh 
