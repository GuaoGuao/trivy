package ospkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestServer_Detect(t *testing.T) {
	type args struct {
		req *proto.OSDetectRequest
	}
	tests := []struct {
		name    string
		args    args
		detect  ospkg.DetectExpectation
		wantRes *proto.DetectResponse
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				req: &proto.OSDetectRequest{
					OsFamily: "alpine",
					OsName:   "3.10.2",
					Packages: []*proto.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detect: ospkg.DetectExpectation{
				Args: ospkg.DetectInput{
					OSFamily: "alpine",
					OSName:   "3.10.2",
					Pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				ReturnArgs: ospkg.DetectOutput{
					Eosl: false,
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2019-0001",
							PkgName:         "musl",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "HIGH",
							}},
					},
				},
			},
			wantRes: &proto.DetectResponse{
				Vulnerabilities: []*proto.Vulnerability{
					{
						VulnerabilityId: "CVE-2019-0001",
						PkgName:         "musl",
						Severity:        proto.Severity_HIGH,
					},
				},
			},
		},
		{
			name: "Detect returns an error",
			args: args{
				req: &proto.OSDetectRequest{
					OsFamily: "alpine",
					OsName:   "3.10.2",
					Packages: []*proto.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detect: ospkg.DetectExpectation{
				Args: ospkg.DetectInput{
					OSFamily: "alpine",
					OSName:   "3.10.2",
					Pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				ReturnArgs: ospkg.DetectOutput{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect vulnerabilities of OS packages: error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := ospkg.NewMockDetector([]ospkg.DetectExpectation{tt.detect})
			mockVulnClient := vulnerability.NewMockVulnClient()

			s := NewServer(mockDetector, mockVulnClient)
			gotRes, err := s.Detect(context.TODO(), tt.args.req)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantRes, gotRes, tt.name)
			mockDetector.AssertExpectations(t)
			mockVulnClient.AssertExpectations(t)
		})
	}
}
