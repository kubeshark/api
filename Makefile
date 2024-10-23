.PHONY: proto

proto:
	protoc --proto_path=. --go_out=.. proto/api.proto
	ls *.pb.go | xargs -n1 -IX bash -c 'sed s/,omitempty// X > X.tmp && mv X{.tmp,}'
