.PHONY: proto

proto:
	protoc --proto_path=. --go_out=.. proto/api.proto
