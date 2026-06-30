package main

import (
	"io"
	"log/slog"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tunnelServer struct {
	gleipnirv1.UnimplementedTunnelServer
}

func (s *tunnelServer) Open(stream grpc.BidiStreamingServer[gleipnirv1.DaemonMessage, gleipnirv1.RelayMessage]) error {
	first, err := stream.Recv()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}

	hello := first.GetHello()
	if hello == nil {
		return status.Errorf(codes.InvalidArgument, "expected Hello as first message")
	}

	hostname := ""
	if hello.Facts != nil {
		hostname = hello.Facts.Hostname
	}
	slog.Info("node connected",
		"node_id", hello.NodeId,
		"daemon_version", hello.DaemonVersion,
		"hostname", hostname,
	)

	if err := stream.Send(&gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Ping{
			Ping: &gleipnirv1.Ping{UnixMillis: time.Now().UnixMilli()},
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "send ping: %v", err)
	}

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hb := msg.GetHeartbeat(); hb != nil {
			slog.Debug("heartbeat", "unix_millis", hb.UnixMillis)
		}
	}
}
