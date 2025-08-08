// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build e2e

package tests

import (
	"io"
	"net"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"github.com/envoyproxy/gateway/internal/gatewayapi"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteAuthzWithClientIP)
}

var TCPRouteAuthzWithClientIP = suite.ConformanceTest{
	ShortName:   "TCPRouteAuthzWithClientIP",
	Description: "Authorization with client IP Allow/Deny list for TCP routes",
	Manifests:   []string{"testdata/tcproute-authorization-client-ip.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		tcpRouteNN := types.NamespacedName{Name: "tcp-backend-authorization-ip", Namespace: ns}
		gwNN := types.NamespacedName{Name: "tcp-authorization-backend", Namespace: ns}
		GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, NewGatewayRef(gwNN), tcpRouteNN)

		ancestorRef := gwapiv1a2.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client, types.NamespacedName{Name: "tcp-backend-authorization-ip-security-policy", Namespace: ns}, suite.ControllerName, ancestorRef)

		t.Run("blocked client IP cannot connect", func(t *testing.T) {
			testTCPRouteWithBackendBlocked(t, suite, "tcp-authorization-backend", "tcp-backend-authorization-ip", "backend-fqdn")
		})
	},
}

func testTCPRouteWithBackendBlocked(t *testing.T, suite *suite.ConformanceTestSuite, gwName, routeName, backendName string) {
	ns := "gateway-conformance-infra"
	routeNN := types.NamespacedName{Name: routeName, Namespace: ns}
	gwNN := types.NamespacedName{Name: gwName, Namespace: ns}
	gwAddr := GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, NewGatewayRef(gwNN), routeNN)
	BackendMustBeAccepted(t, suite.Client, types.NamespacedName{Name: backendName, Namespace: ns})

	testTCPConnectionBlocked(t, gwAddr)
}

func testTCPConnectionBlocked(t *testing.T, gwAddr string) {
	// Try to establish a raw TCP connection
	conn, err := net.DialTimeout("tcp", gwAddr, 5*time.Second)
	if err != nil {
		// Connection refused/timeout - this is what we expect for blocked traffic
		t.Logf("Connection blocked as expected: %v", err)
		return
	}
	defer conn.Close()

	// If connection was established, try sending HTTP request
	req := "GET / HTTP/1.1\r\nHost: " + gwAddr + "\r\nUser-Agent: test-client\r\nAccept: */*\r\n\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Logf("Connection blocked during write as expected: %v", err)
		return
	}

	// Try to read response with a short timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	if err == io.EOF || n == 0 {
		// Empty reply from server - this matches your curl output
		t.Log("Got empty reply from server as expected (connection blocked)")
		return
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Log("Connection timed out as expected (connection blocked)")
			return
		}
		t.Logf("Connection blocked with error as expected: %v", err)
		return
	}

	// If we got here, we received some data, which means the connection was NOT blocked
	response := string(buf[:n])
	t.Fatalf("Expected connection to be blocked, but got response: %s", response)
}
