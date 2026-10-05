package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// A small protobuf service exercises real gRPC framing and status handling.
// Its only credential is a deliberately fake bearer token.
func TestGRPCOverHTTP2Connect(t *testing.T) {
	svc := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkGRPCCredential(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}), grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkGRPCCredential(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}))
	defer svc.Stop()
	svc.RegisterService(&grpc.ServiceDesc{
		ServiceName: "fixture.Echo", HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Unary", Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			msg := new(wrapperspb.BytesValue)
			if err := dec(msg); err != nil {
				return nil, err
			}
			handler := func(ctx context.Context, req any) (any, error) {
				grpc.SetTrailer(ctx, metadata.Pairs("fixture-bin", string([]byte{0, 255, 128})))
				if string(msg.Value) == "deny" {
					return nil, status.Error(codes.PermissionDenied, "fixture denial")
				}
				return msg, nil
			}
			if interceptor == nil {
				return handler(ctx, msg)
			}
			return interceptor(ctx, msg, &grpc.UnaryServerInfo{FullMethod: "/fixture.Echo/Unary"}, handler)
		}}},
		Streams: []grpc.StreamDesc{
			{StreamName: "Client", ClientStreams: true, Handler: func(srv any, ss grpc.ServerStream) error {
				var payload []byte
				for {
					msg := new(wrapperspb.BytesValue)
					err := ss.RecvMsg(msg)
					if err == io.EOF {
						break
					}
					if err != nil {
						return err
					}
					payload = append(payload, msg.Value...)
				}
				return ss.SendMsg(wrapperspb.Bytes(payload))
			}},
			{StreamName: "Server", ServerStreams: true, Handler: func(srv any, ss grpc.ServerStream) error {
				msg := new(wrapperspb.BytesValue)
				if err := ss.RecvMsg(msg); err != nil {
					return err
				}
				for i := 0; i < 3; i++ {
					if err := ss.SendMsg(msg); err != nil {
						return err
					}
				}
				return nil
			}},
			{StreamName: "Bidi", ClientStreams: true, ServerStreams: true, Handler: func(srv any, ss grpc.ServerStream) error {
				for {
					msg := new(wrapperspb.BytesValue)
					err := ss.RecvMsg(msg)
					if err == io.EOF {
						return nil
					}
					if err != nil {
						return err
					}
					if err := ss.SendMsg(msg); err != nil {
						return err
					}
				}
			}},
		},
	}, new(struct{}))
	client, upstream, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" {
			t.Errorf("upstream protocol %s", r.Proto)
		}
		svc.ServeHTTP(w, r)
	}), nil)
	transport := client.Transport.(*http.Transport)
	upstreamURL, _ := url.Parse(upstream.URL)
	proxyURL, err := transport.Proxy(&http.Request{URL: upstreamURL})
	if err != nil {
		t.Fatal(err)
	}
	dialer := func(ctx context.Context, target string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, err
		}
		req := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("fake-session:")))
		if err := req.Write(conn); err != nil {
			conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			conn.Close()
			return nil, fmt.Errorf("CONNECT status %d", resp.StatusCode)
		}
		return conn, nil
	}
	conn, err := grpc.NewClient(upstreamURL.Host, grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: transport.TLSClientConfig.RootCAs})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer placeholder", "fixture-request-bin", string([]byte{0, 255, 128})))
	payload := []byte{0, 255, 128, 1, 2, 3}
	t.Run("unary", func(t *testing.T) {
		got := new(wrapperspb.BytesValue)
		var trailers metadata.MD
		if err := conn.Invoke(ctx, "/fixture.Echo/Unary", wrapperspb.Bytes(payload), got, grpc.Trailer(&trailers)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Value, payload) || len(trailers.Get("fixture-bin")) != 1 || trailers.Get("fixture-bin")[0] != string([]byte{0, 255, 128}) {
			t.Fatalf("payload or binary trailer lost: %v %v", got, trailers)
		}
		if err := conn.Invoke(ctx, "/fixture.Echo/Unary", wrapperspb.Bytes([]byte("deny")), got); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("trailer-only status %v", err)
		}
	})
	t.Run("compressed unary", func(t *testing.T) {
		got := new(wrapperspb.BytesValue)
		if err := conn.Invoke(ctx, "/fixture.Echo/Unary", wrapperspb.Bytes(payload), got, grpc.UseCompressor(gzip.Name)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Value, payload) {
			t.Fatal("compressed payload changed")
		}
	})
	for _, mode := range []string{"Client", "Server", "Bidi"} {
		t.Run(mode, func(t *testing.T) {
			desc := &grpc.StreamDesc{ClientStreams: mode != "Server", ServerStreams: mode != "Client"}
			stream, err := conn.NewStream(ctx, desc, "/fixture.Echo/"+mode)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.SendMsg(wrapperspb.Bytes(payload)); err != nil {
				t.Fatal(err)
			}
			if mode == "Client" {
				if err := stream.SendMsg(wrapperspb.Bytes(payload)); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "Bidi" {
				if err := stream.CloseSend(); err != nil {
					t.Fatal(err)
				}
			}
			replies := 1
			if mode == "Server" {
				replies = 3
			}
			for i := 0; i < replies; i++ {
				got := new(wrapperspb.BytesValue)
				if err := stream.RecvMsg(got); err != nil {
					t.Fatal(err)
				}
				want := payload
				if mode == "Client" {
					want = append(append([]byte{}, payload...), payload...)
				}
				if !bytes.Equal(got.Value, want) {
					t.Fatal(got)
				}
			}
			if mode == "Bidi" { // reply must arrive before closing the client stream
				if err := stream.SendMsg(wrapperspb.Bytes(payload)); err != nil {
					t.Fatal(err)
				}
				if err := stream.RecvMsg(new(wrapperspb.BytesValue)); err != nil {
					t.Fatal(err)
				}
				if err := stream.CloseSend(); err != nil {
					t.Fatal(err)
				}
			}
			if err := stream.RecvMsg(new(wrapperspb.BytesValue)); err != io.EOF {
				t.Fatalf("completion %v", err)
			}
		})
	}
}

func checkGRPCCredential(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get("authorization")) != 1 || md.Get("authorization")[0] != "Bearer fake-credential" {
		return status.Error(codes.Unauthenticated, "fixture credential missing")
	}
	if len(md.Get("fixture-request-bin")) != 1 || md.Get("fixture-request-bin")[0] != string([]byte{0, 255, 128}) {
		return status.Error(codes.InvalidArgument, "binary metadata missing")
	}
	return nil
}
