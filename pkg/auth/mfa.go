package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/appgate/sdp-api-client-go/api/v17/openapi"
	"github.com/appgate/sdpctl/pkg/api"
	"github.com/pkg/browser"
)

type Auth struct {
	APIClient *openapi.APIClient
}

type MinMax struct {
	Min, Max int32
}

func NewAuth(APIClient *openapi.APIClient) *Auth {
	return &Auth{APIClient: APIClient}
}

var ErrPreConditionFailed = errors.New("OTP required")

func (a *Auth) ProviderNames(ctx context.Context) ([]string, error) {
	result := make([]string, 0)
	list, response, err := a.APIClient.LoginApi.IdentityProvidersNamesGet(ctx).Execute()
	if err != nil {
		return nil, api.HTTPErrorResponse(response, err)
	}
	for _, i := range list.GetData() {
		result = append(result, i.GetName())
	}
	sort.Strings(result)

	return result, nil
}

func (a *Auth) Authentication(ctx context.Context, opts openapi.LoginRequest) (*openapi.LoginResponse, *MinMax, error) {
	// opts.SamlResponse = openapi.PtrString(`PHNhbWxwOlJlc3BvbnNlIElEPSJfODk5OGFjYjYtY2ZmMy00MzU5LWFlMGUtZDE0NGI5NzAxNDI3IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMi0wNS0wNVQxNTozNjoxMC44NzlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9wdXJwbGUxMC5hZ2kuYXBwZ2F0ZS5jb206ODQ0My9hZG1pbi9zYW1sIiBJblJlc3BvbnNlVG89Il81OGMxZjQ1NmJlNzM2MTg3YjYxNWQ5MThhNDg0ZGVkOSIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PElzc3VlciB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvYjkzZTgwOWEtNDljNS00YTBmLWE2MDYtODJiODQ2YWNjMzBkLzwvSXNzdWVyPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxBc3NlcnRpb24gSUQ9Il8wZTFkZjI5ZC04YzUzLTRkZGEtYTlmMC1lZGNiZmFmNGJjMDAiIElzc3VlSW5zdGFudD0iMjAyMi0wNS0wNVQxNTozNjoxMC44NzlaIiBWZXJzaW9uPSIyLjAiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48SXNzdWVyPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I5M2U4MDlhLTQ5YzUtNGEwZi1hNjA2LTgyYjg0NmFjYzMwZC88L0lzc3Vlcj48U2lnbmF0dXJlIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48U2lnbmVkSW5mbz48Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PFJlZmVyZW5jZSBVUkk9IiNfMGUxZGYyOWQtOGM1My00ZGRhLWE5ZjAtZWRjYmZhZjRiYzAwIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+VTYvUVZHUGMvN3BaTmxNZVh0QjhtWFFoSTgyaEVockN5bFBDd2RGbWs1ST08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+dmt1eHFhdWNkMk9BV0xzS1g2WmlLNGVodnMzSmJTREtjMzJ4UjVpcW1ZNUVOaEZ5bEdMdloxc3dBTGIzcE5lVDMxV1p2bnFmMjMxUjlrVXE5d3NiM1pzZlFEU0Zya0c4dUhqVFYxY1V1dDBZa2w5YjhzYlJ6UFBCbVM1Zzg4dGhwaVNmeFdGUVhTQnpXYlh5aHFiaHozYTE4SE0veXIzajdvYzBqUW94dE8zQldQTTAzQmxMcFZSWGI4Y0gvSW1mcnZkMXdIcFd6SE9qampUa015Z0pMY3dOVXZwd3dNWjc3d0g1NjBxTkpldEMxTXdZSXdZV2JFNzhjc1BYOXczdlJJK01uS3FnR2VxcG93Y1FRS2p4Zm1vbVVMcnl0YnRTdXpKSWhnT2J0VHVtb1lRSklzUW1pQ3h2ZFV2Z0pzbG1KRDJVS3YwZk5uaDZRNVZtcUc2QitRPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUM4RENDQWRpZ0F3SUJBZ0lRYVJ4ZkJwdjlxcE5GSkVVcDh5a2kyakFOQmdrcWhraUc5dzBCQVFzRkFEQTBNVEl3TUFZRFZRUURFeWxOYVdOeWIzTnZablFnUVhwMWNtVWdSbVZrWlhKaGRHVmtJRk5UVHlCRFpYSjBhV1pwWTJGMFpUQWVGdzB5TURBME1UUXdPVEl6TXpsYUZ3MHlNekEwTVRRd09USXpNemxhTURReE1qQXdCZ05WQkFNVEtVMXBZM0p2YzI5bWRDQkJlblZ5WlNCR1pXUmxjbUYwWldRZ1UxTlBJRU5sY25ScFptbGpZWFJsTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE1dlNkV29DSFBvQVIxVWpCRVlNc1YxeGVpWTFXWitVVEpVbTlyVUNTSnVrSUNPQWdyNjNXc2JXZWdEU2lVMWtEWHkraDdJOVQ2ZktEeGdGWFFXM0M5RUNVaTJUc1E1RmZJQ2t3YWlMRFJ2RnFjVi81ZDdhTEdNakRMVytIVjZNU3dnY045REp3aGdDUGZyZElCbTM5Q0dBck9nd0hKNTdOaEN6WEloWVB1MTBhVVEybHpEbzlXYWRPVVQwNEQ3NGdZN2Q2QWR0eTljZCt6OVRSb3ltTlNzRlQyWmJpNkpHaXVIY2pwUDQxZ3pjZnpTcnlqL005YVdidWFIWmMrZ3FkZkxSQVNjcmVPU1BFTmJOWnN1SmpiTVBJeDdnVWNSVUtPV3RzZnptMlc4S3FCT3RXU1BmeGgwYU5GTEllWFRVWnI2S1lETXEvOVlhN3BqTWEzTWIrMFFJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUJWRld2elpMazExT0xoR2FGMWMyTlJ0a2QxNDNLbmJhUGVNWFA5MER3S3dRcE1saldLc0F6WG13YUt5VWRoZWY3ajVNT2VMb1J3bWFJT2FwNGpZVEZwQzJEMDIvYS81eTlMUGJScHZvNkhCekFTZzN5bWFoZmdjUFFzaTdpaHNKUldYMHpYS3gycy9WTmNDQU05OXNLRDJxdit4dEtIOFppc3JLM3lvMHlIZWQ2aFErbFFEeWt1NFE3a1FuYWJJNlhlWk1ROVZFVXdNa3Rld3FYdUFHRUd4UHNEeTF4T0VKdHZsSXpMc2hzNG9zUS9rZFp6b3NnaFJtTERjR20waUUxK3FCWDJDWHpaOWpGVXhJZHlCYk1kK0cyWjIzVGdBWjVCajVXbGdlRXlHaElia25rQ091YmlVQUNsd3dFWThUcGtZK2FJWW1vMHZXdnJwRG96UnZrazwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxTdWJqZWN0PjxOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmRhbmllbC5uaWxzc29uPC9OYW1lSUQ+PFN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJfNThjMWY0NTZiZTczNjE4N2I2MTVkOTE4YTQ4NGRlZDkiIE5vdE9uT3JBZnRlcj0iMjAyMi0wNS0wNVQxNjozNjoxMC42MjlaIiBSZWNpcGllbnQ9Imh0dHBzOi8vcHVycGxlMTAuYWdpLmFwcGdhdGUuY29tOjg0NDMvYWRtaW4vc2FtbCIvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIyLTA1LTA1VDE1OjMxOjEwLjYyOVoiIE5vdE9uT3JBZnRlcj0iMjAyMi0wNS0wNVQxNjozNjoxMC42MjlaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U+U0RQREVWX1B1cnBsZV9TU09fQWRtaW48L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM+PEF0dHJpYnV0ZVN0YXRlbWVudD48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL3RlbmFudGlkIj48QXR0cmlidXRlVmFsdWU+YjkzZTgwOWEtNDljNS00YTBmLWE2MDYtODJiODQ2YWNjMzBkPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL29iamVjdGlkZW50aWZpZXIiPjxBdHRyaWJ1dGVWYWx1ZT5hNmI1ODNhZC05MmZhLTQzMDQtODU0ZC1kY2YyOWU2MjJiMDQ8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvZGlzcGxheW5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5EYW5pZWwgTmlsc3NvbjwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL2dyb3VwcyI+PEF0dHJpYnV0ZVZhbHVlPkdDUF9TRFBfREVWX0FkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QVdTX1NEUERFVl9Qb3dlclVzZXI8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5BcHBfU0RQRGV2X0dPVC1UZWFtQ2l0eV9Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QXBwX1NEUERldl9QdXJwbGVfU0FNTF9Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QXBwX1NEUERldl9HT1QtVGVzdHJhaWxfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcF9TRV9UZWFtQ2l0eV9Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+U2RwRGV2X1ByaXNtQ0RldkFkbWluPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+U2RwRGV2X1ByaXNtQ1RlYW1DaXR5PC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+U2RwX1NFX1NEUERldm9wczwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcF9Db3JwX0RlZmF1bHRfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPkFwcF9Db3JwX0F1dG9waWxvdERlZmF1bHRfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcF9Db3JwX1RoaW5raWZpY19Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+U2RwRGV2X1ByaXNtQ0J1aWxkPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QVdTX0dJRV9PUEVSQVRJT05TX1NSRV9Qb3dlclVzZXI8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5TZHBfU0VfREVWX0FjY2VzczwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcF9TRV9EZXZfVkNfQWNjZXNzPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QXBwX0NvcnBfU2xhY2tfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPkFwcF9Db3JwX0Fic29yYl9Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48QXR0cmlidXRlVmFsdWU+QXBwX0NvcnBfRXhjbHVkZV9JbnR1bmVfU0RQX0NMSTwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPkFwcF9Db3JwX0ppdmVfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcERldl9QcmlzbUNEZXY8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5BcHBfU0RQRGV2X1ZDX0VOVl9BZG1pbjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPlNkcF9Db3JwX0dpdGh1Yl9Vc2VyczwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPkFwcF9Db3JwX1VkZW15X1VzZXI8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5BcHBfQ29ycF9HaXRIdWJfVXNlcjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPkFwcF9TRFBEZXZfUHVycGxlX1NBTUxfQWRtaW5fUk88L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvaWRlbnRpdHlwcm92aWRlciI+PEF0dHJpYnV0ZVZhbHVlPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2I5M2U4MDlhLTQ5YzUtNGEwZi1hNjA2LTgyYjg0NmFjYzMwZC88L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9jbGFpbXMvYXV0aG5tZXRob2RzcmVmZXJlbmNlcyI+PEF0dHJpYnV0ZVZhbHVlPmh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9hdXRoZW50aWNhdGlvbm1ldGhvZC9wYXNzd29yZDwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vY2xhaW1zL211bHRpcGxlYXV0aG48L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIj48QXR0cmlidXRlVmFsdWU+RGFuaWVsPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3N1cm5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5OaWxzc29uPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI+PEF0dHJpYnV0ZVZhbHVlPmRhbmllbC5uaWxzc29uQGFwcGdhdGUuY29tPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5kYW5pZWwubmlsc3NvbkBhcHBnYXRlLmNvbTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyMi0wNS0wNVQxNTozNTozMi44MDBaIiBTZXNzaW9uSW5kZXg9Il8wZTFkZjI5ZC04YzUzLTRkZGEtYTlmMC1lZGNiZmFmNGJjMDAiPjxBdXRobkNvbnRleHQ+PEF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9BdXRobkNvbnRleHRDbGFzc1JlZj48L0F1dGhuQ29udGV4dD48L0F1dGhuU3RhdGVtZW50PjwvQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+`)
	// TODO lookup login.microsoft saml response redirect localhost
	// start webserver on localhot, initiate redirect loop
	c := a.APIClient
	//     client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
	//         return RedirectAttemptedError
	// }
	var RedirectAttemptedError = errors.New("redirect")
	c.GetConfig().HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fmt.Println("whaa")
		return RedirectAttemptedError
	}
	// redirectURL := "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/saml2?SAMLRequest=fZBBa4QwEIX%2Fisx9bQxG7aAugi0stHSp2z30IjFmW0ETm4mlP7%2FSbmH30uPw5r338fLt1zQGn9rRYE0BUcgg0EbZfjBvBbwc7jcZbMuc5DTyGavFv5tn%2FbFo8sFqNIS%2FSgGLM2glDYRGTprQK2yqxwfkIcPZWW%2BVHSHY1QW0UqeKs6g%2FRSLmtyLpWZ%2BknYq6k2JRl2XrG9Gid4a8NL4AzjjfMLFhyYEJjAWKNIxZ9grB8Y97bYEzJf6Y3SXe%2F3SSSDu%2FxkDZ1Pv67tjuFzePum2ap7bqp8HkN5fJ5fm8nqP8Bg%3D%3D"
	loginResponse, response, err := c.LoginApi.AuthenticationPost(ctx).LoginRequest(opts).Execute()
	if response != nil {
		if response.StatusCode == http.StatusSeeOther {
			l, err := response.Location()
			if err != nil {
				return nil, nil, err
			}
			tokenResponse := make(chan string)
			defer close(tokenResponse)
			mux := http.NewServeMux()
			new := "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/oauth2/v2.0/authorize?client_id=6785aea6-7d09-43ba-9853-59af3a804c8e&code_challenge=qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A29001%2Foidc&response_type=code&scope=openid+profile+offline_access&state=client"
			mux.Handle("/", indexHandler{
				RedirectURL: new,
			})
			mux.Handle("/oidc", oidcHandler{
				Response: tokenResponse,
			})
			server := &http.Server{
				Addr:    ":29001",
				Handler: mux,
			}
			fmt.Println("===AAA==")
			defer server.Close()
			go func() {
				if err := server.ListenAndServe(); err != nil {
					fmt.Printf("[err] %s\n", err) //stderr
				}
			}()
			fmt.Println(l.RequestURI())
			fmt.Println("Updated request URI TO")

			// code challange qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es
			// code verifer M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag
			// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

			// 	http.Redirect(w, r, new, http.StatusSeeOther)

			// })
			// http.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
			// 	fmt.Println("OIDC response")
			// 	fmt.Printf("Request %+v\n", r.RequestURI)
			// 	q := r.URL.Query()
			// 	code := q.Get("code")
			// 	if len(code) < 1 {
			// 		log.Println("Url Param 'code' is missing")
			// 		return
			// 	}
			// 	// {
			// 	//     { "client_id", _oidcProvider.ClientId },
			// 	//     { "grant_type", "authorization_code" },
			// 	//     { "redirect_uri", RedirectUrl },
			// 	//     { "code_verifier", codeVerifier },
			// 	//     { "code", code },
			// 	// };
			// 	form := url.Values{}
			// 	form.Add("client_id", "6785aea6-7d09-43ba-9853-59af3a804c8e")
			// 	form.Add("grant_type", "authorization_code")
			// 	form.Add("redirect_uri", "http://localhost:29001/oidc")
			// 	form.Add("code_verifier", "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag")
			// 	form.Add("code", code)
			// 	req, err := http.NewRequest(http.MethodPost, "https://login.microsoftonline.com/b93e809a-49c5-4a0f-a606-82b846acc30d/oauth2/v2.0/token", strings.NewReader(form.Encode()))
			// 	if err != nil {
			// 		log.Printf("request err1 %s\n", err)
			// 		return
			// 	}
			// 	client := &http.Client{}
			// 	resp, err := client.Do(req)
			// 	if err != nil {
			// 		log.Printf("request err2 %s\n", err)
			// 		return
			// 	}
			// 	fmt.Println(resp.StatusCode)
			// 	body, err := io.ReadAll(resp.Body)
			// 	if err != nil {
			// 		log.Printf("request err2 %s\n", err)
			// 		return
			// 	}
			// 	var data oIDCResponse
			// 	err = json.Unmarshal(body, &data)
			// 	if err != nil {
			// 		log.Printf("request err2 %s\n", err)
			// 		return
			// 	}
			// 	tokenResponse <- data.AccessToken
			// 	fmt.Printf("Results: %+v\n", data)

			// })

			// go http.ListenAndServe(":29001", nil)
			fmt.Println("===BBB==")

			fmt.Println("===CCC==")
			if err := browser.OpenURL("http://localhost:29001"); err != nil {
				return nil, nil, fmt.Errorf("openreader err %w", err)
			}
			fmt.Println("===DDD==")
			// time.Sleep(60 * time.Second)
			t := <-tokenResponse
			customLoginResponse := &openapi.LoginResponse{
				Token: openapi.PtrString(t),
				// Expires: , //
			}
			fmt.Printf("oicd token is %s\n", t)
			return customLoginResponse, nil, nil
		}
	}
	if err != nil {
		if response != nil && response.StatusCode == http.StatusOK {
			if err := browser.OpenReader(response.Body); err != nil {
				return nil, nil, fmt.Errorf("openreader err %w", err)
			}
		}
		if response != nil && response.StatusCode == http.StatusNotAcceptable {
			responseBody, errRead := io.ReadAll(response.Body)
			if errRead != nil {
				return nil, nil, fmt.Errorf("foo 1 %w", errRead)
			}
			errBody := openapi.InlineResponse406{}
			if err := json.Unmarshal(responseBody, &errBody); err != nil {
				return nil, nil, fmt.Errorf("foo 2 %w", err)
			}
			mm := &MinMax{
				Min: errBody.GetMinSupportedVersion(),
				Max: errBody.GetMaxSupportedVersion(),
			}
			return &loginResponse, mm, fmt.Errorf("foo 3 %w", err)
		}
		fmt.Println("Response Start:")
		fmt.Println(response.StatusCode)
		fmt.Println("Response end")
		return nil, nil, api.HTTPErrorResponse(response, fmt.Errorf("foo 4 %w", err))
	}
	return &loginResponse, nil, nil
}

func (a *Auth) Authorization(ctx context.Context, token string) (*openapi.LoginResponse, error) {
	loginResponse, response, err := a.APIClient.LoginApi.AuthorizationGet(ctx).Authorization(token).Execute()
	if err != nil {
		if response != nil && response.StatusCode == http.StatusPreconditionFailed {
			return &loginResponse, ErrPreConditionFailed
		}
		return &loginResponse, api.HTTPErrorResponse(response, err)
	}
	return &loginResponse, nil
}

func (a *Auth) InitializeOTP(ctx context.Context, password, token string) (openapi.InlineResponse2007, error) {
	o := openapi.InlineObject7{UserPassword: openapi.PtrString(password)}
	r, response, err := a.APIClient.LoginApi.AuthenticationOtpInitializePost(ctx).Authorization(token).InlineObject7(o).Execute()
	if err != nil {
		return r, api.HTTPErrorResponse(response, err)
	}
	return r, nil
}

var ErrInvalidOneTimePassword = errors.New("Invalid one-time password.")

func (a *Auth) PushOTP(ctx context.Context, answer, token string) (*openapi.LoginResponse, error) {
	o := openapi.InlineObject6{
		Otp: answer,
	}
	newToken, response, err := a.APIClient.LoginApi.AuthenticationOtpPost(ctx).InlineObject6(o).Authorization(token).Execute()
	if err != nil {
		if response != nil && response.StatusCode == http.StatusUnauthorized {
			return &newToken, ErrInvalidOneTimePassword
		}
		return nil, api.HTTPErrorResponse(response, err)
	}
	return &newToken, nil
}
