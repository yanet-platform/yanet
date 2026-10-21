all:
	docker build -f builder/Dockerfile -t yanetplatform/builder builder
	docker build -f yanet/Dockerfile -t yanetplatform/yanet ../
	docker build -f yanet-announcer/Dockerfile -t yanetplatform/yanet-announcer ../
