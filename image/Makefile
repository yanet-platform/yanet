all:
	docker build -f builder/Dockerfile -t yanetplatform/builder builder
	docker build -f builder/Dockerfile.ubuntu18.04 -t yanetplatform/builder_ubuntu18.04 builder
	docker build -f yanet/Dockerfile -t yanetplatform/yanet ../
	docker build -f yanet/Dockerfile.ubuntu18.04 -t yanetplatform/yanet_ubuntu18.04 ../
	docker build -f yanet-announcer/Dockerfile -t yanetplatform/yanet-announcer ../
