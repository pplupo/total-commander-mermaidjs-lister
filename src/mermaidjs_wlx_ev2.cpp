// Mermaid.js WebView Lister (Tiny)
// Features:
//  - WebView2 runtime loaded dynamically (no static import)
//
// Build: CMake -> MermaidJsWebView.wlx64

#include <windows.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <wrl.h>
#include <wrl/event.h>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <cwchar>

#include <wincodec.h>

#include "WebView2.h"

#ifndef MERMAIDJS_WEB_BUILD
#define MERMAIDJS_WEB_BUILD 0
#endif

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "windowscodecs.lib")

using namespace Microsoft::WRL;

// ---------------------- Config ----------------------
static std::wstring g_prefer    = L"svg";           // "svg" or "png"
static std::string  g_detectA   = R"(EXT=".MERMAID" | EXT=".MMD")";

static std::wstring g_mmdcPath;                     // If empty: auto-detect moduleDir\mmdc.(bat|cmd|exe)
static std::wstring g_logPath;                      // If empty: moduleDir\mermaidjswebview.log
static DWORD        g_mmdcTimeoutMs = 8000;
static bool         g_logEnabled = true;

static bool         g_cfgLoaded = false;

static std::mutex   g_logMutex;
static bool         g_logSessionStarted = false;

static std::string ToUtf8(const std::wstring& w);

static std::wstring FormatTimestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static void AppendLog(const std::wstring& message) {
    if (!g_logEnabled || g_logPath.empty()) return;
    std::lock_guard<std::mutex> lock(g_logMutex);
    HANDLE h = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    if (!g_logSessionStarted) {
        LARGE_INTEGER size{};
        if (GetFileSizeEx(h, &size) && size.QuadPart > 0) {
            std::string sep = "\r\n";
            DWORD written = 0;
            WriteFile(h, sep.c_str(), (DWORD)sep.size(), &written, nullptr);
        }
        std::wstring header = FormatTimestamp() + L"--- Mermaid.js WebView session start ---\r\n";
        std::string headerUtf8 = ToUtf8(header);
        if (!headerUtf8.empty()) {
            DWORD written = 0;
            WriteFile(h, headerUtf8.data(), (DWORD)headerUtf8.size(), &written, nullptr);
        }
        g_logSessionStarted = true;
    }
    std::wstring line = FormatTimestamp() + message + L"\r\n";
    std::string utf8 = ToUtf8(line);
    if (!utf8.empty()) {
        DWORD written = 0;
        WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
    }
    CloseHandle(h);
}

static bool ClipboardSetUnicodeText(const std::wstring& text) {
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!mem) {
        return false;
    }
    void* ptr = GlobalLock(mem);
    if (!ptr) {
        GlobalFree(mem);
        return false;
    }
    memcpy(ptr, text.c_str(), bytes);
    GlobalUnlock(mem);
    if (!SetClipboardData(CF_UNICODETEXT, mem)) {
        GlobalFree(mem);
        return false;
    }
    return true;
}

static bool ClipboardSetBinaryData(UINT format, const void* data, size_t size) {
    if (!data || !size) {
        return false;
    }
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, size);
    if (!mem) {
        return false;
    }
    void* ptr = GlobalLock(mem);
    if (!ptr) {
        GlobalFree(mem);
        return false;
    }
    memcpy(ptr, data, size);
    GlobalUnlock(mem);
    if (!SetClipboardData(format, mem)) {
        GlobalFree(mem);
        return false;
    }
    return true;
}

static bool CreateDibFromPng(const std::vector<unsigned char>& png,
                             std::vector<unsigned char>& outDib) {
    outDib.clear();
    if (png.empty()) {
        return false;
    }

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool needUninit = false;
    if (hrInit == RPC_E_CHANGED_MODE) {
        hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (hrInit == RPC_E_CHANGED_MODE) {
            hrInit = S_OK;
        } else if (SUCCEEDED(hrInit)) {
            needUninit = (hrInit == S_OK || hrInit == S_FALSE);
        }
    } else if (SUCCEEDED(hrInit)) {
        needUninit = (hrInit == S_OK || hrInit == S_FALSE);
    }

    if (FAILED(hrInit)) {
        return false;
    }

    ComPtr<IWICImagingFactory> factory;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) {
        if (needUninit) CoUninitialize();
        return false;
    }

    IStream* rawStream = SHCreateMemStream(png.data(), static_cast<UINT>(png.size()));
    if (!rawStream) {
        if (needUninit) CoUninitialize();
        return false;
    }
    ComPtr<IStream> stream;
    stream.Attach(rawStream);

    ComPtr<IWICBitmapDecoder> decoder;
    hr = factory->CreateDecoderFromStream(stream.Get(), nullptr, WICDecodeMetadataCacheOnLoad,
                                          &decoder);
    if (FAILED(hr) || !decoder) {
        if (needUninit) CoUninitialize();
        return false;
    }

    ComPtr<IWICBitmapFrameDecode> frame;
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr) || !frame) {
        if (needUninit) CoUninitialize();
        return false;
    }

    ComPtr<IWICFormatConverter> converter;
    hr = factory->CreateFormatConverter(&converter);
    if (FAILED(hr) || !converter) {
        if (needUninit) CoUninitialize();
        return false;
    }

    hr = converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppBGRA,
                               WICBitmapDitherTypeNone, nullptr, 0.0f,
                               WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) {
        if (needUninit) CoUninitialize();
        return false;
    }

    UINT width = 0, height = 0;
    hr = converter->GetSize(&width, &height);
    if (FAILED(hr) || width == 0 || height == 0) {
        if (needUninit) CoUninitialize();
        return false;
    }

    const UINT stride = width * 4;
    const UINT imageSize = stride * height;
    outDib.resize(sizeof(BITMAPV5HEADER) + imageSize);
    auto* header = reinterpret_cast<BITMAPV5HEADER*>(outDib.data());
    ZeroMemory(header, sizeof(BITMAPV5HEADER));
    header->bV5Size = sizeof(BITMAPV5HEADER);
    header->bV5Width = static_cast<LONG>(width);
    header->bV5Height = -static_cast<LONG>(height);
    header->bV5Planes = 1;
    header->bV5BitCount = 32;
    header->bV5Compression = BI_BITFIELDS;
    header->bV5RedMask   = 0x00FF0000;
    header->bV5GreenMask = 0x0000FF00;
    header->bV5BlueMask  = 0x000000FF;
    header->bV5AlphaMask = 0xFF000000;
    header->bV5SizeImage = imageSize;

    BYTE* pixels = outDib.data() + sizeof(BITMAPV5HEADER);
    hr = converter->CopyPixels(nullptr, stride, imageSize, pixels);

    if (needUninit) {
        CoUninitialize();
    }

    if (FAILED(hr)) {
        outDib.clear();
        return false;
    }

    return true;
}

// ---------------------- Helpers ----------------------
static std::wstring GetModuleDir() {
    wchar_t path[MAX_PATH]{}; HMODULE hm{};
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&GetModuleDir, &hm);
    GetModuleFileNameW(hm, path, MAX_PATH);
    PathRemoveFileSpecW(path);
    return path;
}

static bool FileExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void ReplaceAll(std::wstring& inout, const std::wstring& from, const std::wstring& to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = inout.find(from, pos)) != std::wstring::npos) {
        inout.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::wstring EscapeForHtmlText(const std::wstring& input) {
    std::wstring result = input;
    ReplaceAll(result, L"&", L"&amp;");
    ReplaceAll(result, L"<", L"&lt;");
    ReplaceAll(result, L">", L"&gt;");
    return result;
}

static std::wstring EscapeForHtmlAttribute(const std::wstring& input) {
    std::wstring result = input;
    ReplaceAll(result, L"&", L"&amp;");
    ReplaceAll(result, L"\"", L"&quot;");
    ReplaceAll(result, L"'", L"&#39;");
    ReplaceAll(result, L"<", L"&lt;");
    ReplaceAll(result, L">", L"&gt;");
    return result;
}

static std::wstring ExtractFileStem(const std::wstring& path) {
    if (path.empty()) {
        return L"diagram";
    }
    const wchar_t* base = PathFindFileNameW(path.c_str());
    std::wstring stem = base ? std::wstring(base) : path;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        stem.erase(dot);
    }
    if (stem.empty()) {
        stem = L"diagram";
    }
    return stem;
}

static void ApplySourceNamePlaceholder(std::wstring& html, const std::wstring& path) {
    const std::wstring stem = ExtractFileStem(path);
    const std::wstring escaped = EscapeForHtmlAttribute(stem);
    ReplaceAll(html, L"{{SOURCE_NAME}}", escaped);
}

static std::wstring ExtractJsonStringField(const std::wstring& json, const std::wstring& field) {
    if (json.empty() || field.empty()) {
        return std::wstring();
    }
    const std::wstring needle = L"\"" + field + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) {
        return std::wstring();
    }
    pos = json.find(L':', pos + needle.size());
    if (pos == std::wstring::npos) {
        return std::wstring();
    }
    size_t quote = json.find_first_of(L"\"'", pos + 1);
    if (quote == std::wstring::npos) {
        return std::wstring();
    }
    const wchar_t delimiter = json[quote];
    size_t end = json.find(delimiter, quote + 1);
    if (end == std::wstring::npos) {
        return std::wstring();
    }
    return json.substr(quote + 1, end - quote - 1);
}

static std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    if (n > 0) ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    if (n > 0) ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring ReadFileUtf16OrAnsi(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        AppendLog(L"ReadFileUtf16OrAnsi: failed to open file " + std::wstring(path ? path : L"<null>") +
                  L" (error=" + std::to_wstring(GetLastError()) + L")");
        return L"";
    }
    DWORD size = GetFileSize(h, nullptr);
    std::string bytes; bytes.resize(size ? size : 0);
    DWORD read = 0;
    if (size && (!ReadFile(h, bytes.data(), size, &read, nullptr) || read != size)) {
        AppendLog(L"ReadFileUtf16OrAnsi: short read for file " + std::wstring(path ? path : L"<null>") +
                  L" (wanted=" + std::to_wstring(size) + L", got=" + std::to_wstring(read) + L")");
    }
    CloseHandle(h);

    if (bytes.size() >= 2 && (unsigned char)bytes[0]==0xFF && (unsigned char)bytes[1]==0xFE) {
        std::wstring w((wchar_t*)(bytes.data()+2), (bytes.size()-2)/2); return w;
    }
    if (bytes.size() >= 3 && (unsigned char)bytes[0]==0xEF && (unsigned char)bytes[1]==0xBB && (unsigned char)bytes[2]==0xBF) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, bytes.data()+3, (int)bytes.size()-3, nullptr, 0);
        std::wstring w(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, bytes.data()+3, (int)bytes.size()-3, w.data(), wlen);
        return w;
    }
    int wlen = MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), w.data(), wlen);
    return w;
}

static bool WriteBufferToFile(const std::wstring& path, const void* data, size_t size) {
    if (size > MAXDWORD) {
        AppendLog(L"WriteBufferToFile: payload too large for Win32 WriteFile: " + std::to_wstring(static_cast<unsigned long long>(size)) + L" bytes");
        return false;
    }
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        AppendLog(L"WriteBufferToFile: failed to create file " + path + L" (error=" + std::to_wstring(GetLastError()) + L")");
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr);
    DWORD lastErr = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    if (!ok || written != size) {
        AppendLog(L"WriteBufferToFile: failed to write file " + path + L" (error=" + std::to_wstring(lastErr) + L", written=" + std::to_wstring(written) + L"/" + std::to_wstring(static_cast<unsigned long long>(size)) + L")");
        return false;
    }
    return true;
}

static bool TryAutoDetectMmdcCli(std::wstring& outPath) {
    const std::wstring dir = GetModuleDir();
    const wchar_t* candidates[] = {L"mmdc.bat", L"mmdc.cmd", L"mmdc.exe"};
    for (const wchar_t* name : candidates) {
        const std::wstring candidate = dir + L"\\" + name;
        if (FileExistsW(candidate)) {
            outPath = candidate;
            return true;
        }
    }
    return false;
}

static void LoadConfigIfNeeded() {
    if (g_cfgLoaded) return;
    g_cfgLoaded = true;

    const std::wstring moduleDir = GetModuleDir();
    const std::wstring ini = moduleDir + L"\\mermaidjswebview.ini";
    wchar_t buf[2048];

    if (GetPrivateProfileStringW(L"render", L"prefer", L"", buf, 2048, ini.c_str()) > 0 && buf[0]) g_prefer = buf;

    if (GetPrivateProfileStringW(L"detect", L"string", L"", buf, 2048, ini.c_str()) > 0 && buf[0]) {
        int need = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
        std::string utf8(need ? need - 1 : 0, '\0');
        if (need > 1) WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8.data(), need - 1, nullptr, nullptr);
        if (!utf8.empty()) g_detectA = utf8;
    }

    if (GetPrivateProfileStringW(L"mmdc", L"cli", L"", buf, 2048, ini.c_str()) > 0 && buf[0]) {
        g_mmdcPath = buf;
        if (PathIsRelativeW(g_mmdcPath.c_str())) {
            g_mmdcPath = moduleDir + L"\\" + g_mmdcPath;
        }
    }
    DWORD tmo = GetPrivateProfileIntW(L"mmdc", L"timeout_ms", 0, ini.c_str());
    if (tmo > 0) g_mmdcTimeoutMs = tmo;

    int logEnabled = GetPrivateProfileIntW(L"debug", L"log_enabled", 1, ini.c_str());
    g_logEnabled = (logEnabled != 0);

    if (GetPrivateProfileStringW(L"debug", L"log", L"", buf, 2048, ini.c_str()) > 0 && buf[0]) {
        g_logPath = buf;
        if (PathIsRelativeW(g_logPath.c_str())) {
            g_logPath = moduleDir + L"\\" + g_logPath;
        }
    }

    if (g_logEnabled) {
        if (g_logPath.empty()) {
            g_logPath = moduleDir + L"\\mermaidjswebview.log";
        }
    } else {
        g_logPath.clear();
    }

    bool needDetectCli = g_mmdcPath.empty();
    if (!g_mmdcPath.empty() && !FileExistsW(g_mmdcPath)) {
        AppendLog(L"LoadConfig: configured Mermaid CLI not found at " + g_mmdcPath + L". Attempting auto-detect.");
        needDetectCli = true;
    }
    if (needDetectCli) {
        std::wstring detected;
        if (TryAutoDetectMmdcCli(detected)) {
            g_mmdcPath.swap(detected);
        }
    }

    std::wstringstream cfg;
    cfg << L"Config loaded. prefer=" << g_prefer
        << L", cli=" << (g_mmdcPath.empty() ? L"<auto>" : g_mmdcPath)
        << L", timeoutMs=" << g_mmdcTimeoutMs
        << L", logEnabled=" << (g_logEnabled ? L"1" : L"0")
        << L", log=" << (g_logPath.empty() ? L"<disabled>" : g_logPath);
    AppendLog(cfg.str());
}

static std::wstring ToLowerTrim(const std::wstring& in) {
    std::wstring s = in;
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](wchar_t c){ return !iswspace(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](wchar_t c){ return !iswspace(c); }).base(), s.end());
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}
static std::wstring GetCommandProcessor() {
    wchar_t buf[MAX_PATH]{};
    DWORD len = GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::wstring value(buf, len);
        if (!value.empty() && value.front() == L'"' && value.back() == L'"') {
            value = value.substr(1, value.size() - 2);
        }
        if (!value.empty()) {
            return value;
        }
    }
    return L"cmd.exe";
}

// Simple base64 encoder (for PNG data URLs)
static std::string Base64(const std::vector<unsigned char>& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0, n = in.size();
    out.reserve(((n + 2) / 3) * 4);
    while (i + 2 < n) {
        unsigned v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
        i += 3;
    }
    if (i + 1 == n) {
        unsigned v = (in[i] << 16);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == n) {
        unsigned v = (in[i] << 16) | (in[i+1] << 8);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

static int Base64DecodeChar(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return static_cast<int>(c - L'A');
    if (c >= L'a' && c <= L'z') return static_cast<int>(c - L'a' + 26);
    if (c >= L'0' && c <= L'9') return static_cast<int>(c - L'0' + 52);
    if (c == L'+') return 62;
    if (c == L'/') return 63;
    return -1;
}

static std::vector<unsigned char> Base64Decode(const std::wstring& in) {
    std::vector<unsigned char> out;
    int val = 0;
    int valb = -8;
    for (wchar_t wc : in) {
        if (wc == L'=' || wc == L'\r' || wc == L'\n' || wc == L' ' || wc == L'\t') {
            if (wc == L'=') {
                break;
            }
            continue;
        }
        int decoded = Base64DecodeChar(wc);
        if (decoded < 0) {
            continue;
        }
        val = (val << 6) + decoded;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Run "mmdc.bat -i - -o - -e (svg|png)" and capture stdout.
static bool RunMmdcCli(const std::wstring& umlTextW,
                             bool preferSvg,
                             std::wstring& outSvg,
                             std::vector<unsigned char>& outPng) {
    outSvg.clear();
    outPng.clear();

    if (g_mmdcPath.empty()) {
        AppendLog(L"RunMmdcCli: cli path is empty");
        return false;
    }
    if (!FileExistsW(g_mmdcPath)) {
        AppendLog(L"RunMmdcCli: cli not found at " + g_mmdcPath);
        return false;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE hInR = nullptr, hInW = nullptr;
    HANDLE hOutR = nullptr, hOutW = nullptr;

    if (!CreatePipe(&hInR, &hInW, &sa, 0)) {
        AppendLog(L"RunMmdcCli: failed to create stdin pipe");
        return false;
    }
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) {
        AppendLog(L"RunMmdcCli: failed to create stdout pipe");
        CloseHandle(hInR);
        CloseHandle(hInW);
        return false;
    }

    SetHandleInformation(hInR,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hOutW, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(hInW,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);

    const std::wstring comspec = GetCommandProcessor();
    std::wstringstream cli;
    cli << L"\"" << g_mmdcPath << L"\"" << L" -q -i - -o -";
    if (preferSvg) {
        cli << L" -e svg";
    } else {
        cli << L" -e png";
    }

    std::wstring commandLine = L"\"" + comspec + L"\"" + L" /C \"" + cli.str() + L"\"";
    std::vector<wchar_t> cmdBuffer(commandLine.begin(), commandLine.end());
    cmdBuffer.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = hInR;
    si.hStdOutput = hOutW;
    si.hStdError  = hOutW;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmdBuffer.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hOutW);
    CloseHandle(hInR);

    if (!ok) {
        AppendLog(L"RunMmdcCli: CreateProcessW failed with error " + std::to_wstring(GetLastError()));
        CloseHandle(hInW);
        CloseHandle(hOutR);
        return false;
    }

    std::string umlUtf8 = ToUtf8(umlTextW);
    DWORD written = 0;
    if (!umlUtf8.empty()) {
        if (!WriteFile(hInW, umlUtf8.data(), static_cast<DWORD>(umlUtf8.size()), &written, nullptr)) {
            AppendLog(L"RunMmdcCli: failed to write Mermaid definition to stdin (error=" + std::to_wstring(GetLastError()) + L")");
        }
    }
    CloseHandle(hInW);

    std::vector<unsigned char> buffer;
    buffer.reserve(64 * 1024);
    unsigned char tmp[16 * 1024];
    DWORD got = 0;
    for (;;) {
        if (!ReadFile(hOutR, tmp, sizeof(tmp), &got, nullptr) || got == 0) break;
        buffer.insert(buffer.end(), tmp, tmp + got);
        if (buffer.size() > (50 * 1024 * 1024)) break;
        DWORD wr = WaitForSingleObject(pi.hProcess, 0);
        if (wr == WAIT_OBJECT_0) {
            while (ReadFile(hOutR, tmp, sizeof(tmp), &got, nullptr) && got) {
                buffer.insert(buffer.end(), tmp, tmp + got);
            }
            break;
        }
    }
    CloseHandle(hOutR);

    DWORD wr = WaitForSingleObject(pi.hProcess, g_mmdcTimeoutMs);
    if (wr == WAIT_FAILED) {
        AppendLog(L"RunMmdcCli: WaitForSingleObject failed with error " + std::to_wstring(GetLastError()));
    } else if (wr == WAIT_TIMEOUT) {
        AppendLog(L"RunMmdcCli: timeout after " + std::to_wstring(g_mmdcTimeoutMs) + L" ms");
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hThread);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);

    if (buffer.empty()) {
        AppendLog(L"RunMmdcCli: process produced no output. exitCode=" + std::to_wstring(exitCode));
        return false;
    }

    if (preferSvg) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0,
                                       reinterpret_cast<const char*>(buffer.data()), static_cast<int>(buffer.size()),
                                       nullptr, 0);
        if (wlen <= 0) {
            AppendLog(L"RunMmdcCli: failed to decode SVG output");
            return false;
        }
        std::wstring svg(static_cast<size_t>(wlen), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(buffer.data()), static_cast<int>(buffer.size()),
                            svg.data(), wlen);
        outSvg.swap(svg);
    } else {
        outPng.swap(buffer);
    }
    AppendLog(L"RunMmdcCli: success. exitCode=" + std::to_wstring(exitCode) +
              L", outputLength=" + std::to_wstring(static_cast<unsigned long long>(preferSvg ? outSvg.size() : outPng.size())));
    return true;
}

static bool BuildHtmlFromMmdcRender(const std::wstring& umlText,
                                    const std::wstring& sourcePath,
                                    bool preferSvg,
                                    std::wstring& outHtml,
                                    std::wstring* outSvg,
                                    std::vector<unsigned char>* outPng);

#if MERMAIDJS_WEB_BUILD

static std::wstring BuildWebShellHtml(const std::wstring& body, bool preferSvg) {
    
static const wchar_t kHtmlPart1[] = LR"HTML(<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>MermaidJs Viewer</title>
  <style>
    :root { color-scheme: light dark; }
    html, body { height: 100%; }
    body { margin: 0; background: color-mix(in srgb, Canvas 92%, CanvasText 8%); color: CanvasText; font: 13px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; position: relative; }
    #toolbar { position: fixed; top: 8px; left: 8px; display: flex; gap: 6px; z-index: 10; }
    #toolbar button, #toolbar select { padding: 6px 10px; border-radius: 6px; border: 1px solid color-mix(in oklab, Canvas 70%, CanvasText 30%); background: color-mix(in oklab, Canvas 92%, CanvasText 8%); color: inherit; font: inherit; cursor: pointer; }
    #toolbar button:hover, #toolbar select:hover { background: color-mix(in oklab, Canvas 88%, CanvasText 12%); }
    #toolbar button:disabled, #toolbar select:disabled { opacity: 0.6; cursor: not-allowed; }
    #root { padding: 64px 16px 16px 16px; display: grid; place-items: start center; box-sizing: border-box; }
    #diagram-frame { max-width: min(1100px, 100%); width: 100%; background: #ffffff; border-radius: 12px; padding: 18px; box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08); box-sizing: border-box; }
    #diagram-container { width: 100%; }
    #diagram-container svg { background-color: #ffffff !important; color: #000000 !important; }
    #diagram-container .mermaid { background-color: #ffffff !important; color: #000000 !important; }
    #png-preview { display: none; max-width: 100%; height: auto; }
    img, svg { max-width: 100%; height: auto; }
    .err { padding: 12px 14px; border-radius: 10px; background: color-mix(in oklab, Canvas 85%, red 15%); }
  </style>
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({ startOnLoad: true, theme: 'default', themeVariables: { background: '#ffffff' } });
  </script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/save-svg-as-png/1.4.17/saveSvgAsPng.min.js"></script>
</head>
<body data-format="{{FORMAT}}" data-source-name="{{SOURCE_NAME}}">
  <div id="toolbar">
    <button id="btn-refresh" type="button">Refresh</button>
    <button id="btn-save" type="button">Save as...</button>
    <select id="format-select">
      <option value="svg">SVG</option>
      <option value="png">PNG</option>
    </select>
    <button id="btn-copy" type="button">Copy to clipboard</button>
  </div>
  <div id="root">
    <div id="diagram-frame">
      <div id="diagram-container">
        {{BODY}}
      </div>
      <img id="png-preview" alt="Mermaid PNG preview"/>
    </div>
  </div>
  <script>
    const bodyEl = document.body;
    const diagramContainer = document.getElementById('diagram-container');
    const pngPreview = document.getElementById('png-preview');
    const refreshButton = document.getElementById('btn-refresh');
    const saveButton = document.getElementById('btn-save');
    const copyButton = document.getElementById('btn-copy');
    const formatSelect = document.getElementById('format-select');

    const setFormat = (value) => {
      if (bodyEl && bodyEl.dataset) {
        bodyEl.dataset.format = value;
      }
    };
    const getFormat = () => bodyEl?.dataset?.format || 'svg';
    const getSvgElement = () => diagramContainer?.querySelector('svg');
    const getFileBase = () => bodyEl?.dataset?.sourceName || 'mermaid-diagram';
    const buildFileName = (ext) => {
      const base = getFileBase();
      return (base || 'mermaid-diagram') + '.' + ext;
    };

    const renderState = {
      svgText: '',
      pngDataUrl: '',
    };
    let lastSentSvg = '';
    let lastSentPng = '';
    let lastSentFormat = '';
    let pngRequestId = 0;

    const storageKey = 'mermaidjs-web-format';

    const isConnected = () => !!(window.chrome && window.chrome.webview);

    const ensureSvgAppearance = (svg) => {
      if (!svg) { return; }
      svg.style.backgroundColor = '#ffffff';
      svg.style.color = '#000000';
    };

    const encodeBase64 = (text) => {
      try {
        if (typeof TextEncoder !== 'undefined') {
          const bytes = new TextEncoder().encode(text);
          let binary = '';
          bytes.forEach((b) => { binary += String.fromCharCode(b); });
          return window.btoa(binary);
        }
        return window.btoa(unescape(encodeURIComponent(text)));
      } catch (err) {
        console.warn('Unable to encode payload as base64', err);
        return '';
      }
    };

    const extractBase64FromDataUrl = (dataUrl) => {
      if (!dataUrl) { return ''; }
      const comma = dataUrl.indexOf(',');
      return comma >= 0 ? dataUrl.slice(comma + 1) : '';
    };

    const notifyHost = () => {
      if (!isConnected()) { return; }
      const format = getFormat();
      const svgBase64 = renderState.svgText ? encodeBase64(renderState.svgText) : '';
      const pngBase64 = renderState.pngDataUrl ? extractBase64FromDataUrl(renderState.pngDataUrl) : '';
      if (svgBase64 === lastSentSvg && pngBase64 === lastSentPng && format === lastSentFormat) {
        return;
      }
      lastSentSvg = svgBase64;
      lastSentPng = pngBase64;
      lastSentFormat = format;
      try {
        window.chrome.webview.postMessage({
          type: 'rendered',
          format,
          svgBase64,
          pngBase64,
        });
      } catch (err) {
        console.warn('Failed to notify host about rendered diagram', err);
      }
    };

    const hasRenderable = () => {
      const format = getFormat();
      if (format === 'png') {
        return !!renderState.pngDataUrl;
      }
      return !!renderState.svgText;
    };

    const applyFormatDisplay = () => {
      const svg = getSvgElement();
      if (!svg || !pngPreview) { return; }
      const format = getFormat();
      if (format === 'png' && renderState.pngDataUrl) {
        pngPreview.src = renderState.pngDataUrl;
        pngPreview.style.display = 'block';
        svg.style.visibility = 'hidden';
        svg.style.position = 'absolute';
        svg.style.pointerEvents = 'none';
      } else {
        pngPreview.style.display = 'none';
        pngPreview.removeAttribute('src');
        svg.style.removeProperty('visibility');
        svg.style.removeProperty('position');
        svg.style.removeProperty('pointer-events');
      }
    };

    const updateRefreshState = () => {
      if (!refreshButton) { return; }
      const connected = isConnected();
      refreshButton.disabled = !connected;
      if (!connected) {
        refreshButton.title = 'Available inside Total Commander';
        window.setTimeout(updateRefreshState, 1000);
      } else {
        refreshButton.removeAttribute('title');
      }
    };

    const updateSaveState = () => {
      if (!saveButton) { return; }
      if (hasRenderable()) {
        saveButton.disabled = false;
        saveButton.removeAttribute('title');
      } else {
        saveButton.disabled = true;
        saveButton.title = 'Diagram not rendered yet';
      }
    };

    const updateCopyState = () => {
      if (!copyButton) { return; }
      if (!hasRenderable()) {
        copyButton.disabled = true;
        copyButton.title = 'Diagram not rendered yet';
        return;
      }
      if (isConnected()) {
        copyButton.disabled = false;
        copyButton.removeAttribute('title');
        return;
      }
      if (!navigator.clipboard) {
        copyButton.disabled = true;
        copyButton.title = 'Clipboard access is unavailable';
        window.setTimeout(updateCopyState, 1000);
        return;
      }
      if (getFormat() === 'png' && typeof window.ClipboardItem === 'undefined') {
        copyButton.disabled = true;
        copyButton.title = 'Clipboard image support is unavailable';
        window.setTimeout(updateCopyState, 1000);
        return;
      }
      copyButton.disabled = false;
      copyButton.title = 'Host unavailable – using browser clipboard';
      window.setTimeout(updateCopyState, 1000);
    };

    const updateRenderOutputs = () => {
      const svgElement = getSvgElement();
      if (!svgElement) {
        renderState.svgText = '';
        renderState.pngDataUrl = '';
        applyFormatDisplay();
        updateSaveState();
        updateCopyState();
        notifyHost();
        return;
      }
      ensureSvgAppearance(svgElement);
      const svgCode = new XMLSerializer().serializeToString(svgElement);
      renderState.svgText = svgCode;
      renderState.pngDataUrl = '';
      applyFormatDisplay();
      updateSaveState();
      updateCopyState();
      notifyHost();
      if (window.saveSvgAsPng && saveSvgAsPng.svgAsPngUri) {
        const requestId = ++pngRequestId;
        saveSvgAsPng.svgAsPngUri(svgElement, { backgroundColor: '#ffffff' }, (uri) => {
          if (requestId !== pngRequestId) { return; }
          renderState.pngDataUrl = uri || '';
          applyFormatDisplay();
          updateSaveState();
          updateCopyState();
          notifyHost();
        });
      }
    };

    const saveDiagram = () => {
      if (!hasRenderable()) {
        alert('Diagram not rendered yet.');
        return;
      }
      const format = getFormat();
      const fileName = buildFileName(format === 'svg' ? 'svg' : 'png');
      if (isConnected()) {
        window.chrome.webview.postMessage({ type: 'saveAs' });
        return;
      }
      if (format === 'svg') {
        const blob = new Blob([renderState.svgText], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      } else {
        const link = document.createElement('a');
        link.href = renderState.pngDataUrl;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }
    };

    const copyDiagram = async () => {
      if (!hasRenderable()) {
        alert('Diagram not rendered yet.');
        return;
      }
      const format = getFormat();
      if (isConnected()) {
        window.chrome.webview.postMessage({ type: 'copy' });
        return;
      }
      if (!navigator.clipboard) {
        alert('Clipboard access is unavailable.');
        return;
      }
      try {
        if (format === 'svg') {
          await navigator.clipboard.writeText(renderState.svgText);
          alert('SVG code copied to clipboard!');
        } else {
          if (typeof window.ClipboardItem === 'undefined') {
            alert('Clipboard image support is unavailable.');
            return;
          }
          const response = await fetch(renderState.pngDataUrl);
          const blob = await response.blob();
          await navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]);
          alert('PNG image copied to clipboard!');
        }
      } catch (err) {
        console.error('Failed to copy image to clipboard: ', err);
        alert('Failed to copy. Please check the browser console for more details.');
      }
    };

    try {
      const stored = window.localStorage?.getItem(storageKey);
      if (stored === 'svg' || stored === 'png') {
        setFormat(stored);
        if (formatSelect) {
          formatSelect.value = stored;
        }
      }
    } catch (err) {}

    if (formatSelect) {
      formatSelect.value = getFormat();
    }

    if (formatSelect) {
      formatSelect.addEventListener('change', () => {
        const value = formatSelect.value;
        setFormat(value);
        try {
          window.localStorage?.setItem(storageKey, value);
        } catch (err) {}
        applyFormatDisplay();
        updateSaveState();
        updateCopyState();
        notifyHost();
      });
    }

    if (refreshButton) {
      updateRefreshState();
      refreshButton.addEventListener('click', () => {
        if (isConnected()) {
          window.chrome.webview.postMessage({ type: 'refresh' });
        } else {
          window.location.reload();
        }
      });
    }

    if (saveButton) {
      saveButton.addEventListener('click', saveDiagram);
    }

    if (copyButton) {
      copyButton.addEventListener('click', copyDiagram);
    }

    document.addEventListener('keydown', (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'c') {
        ev.preventDefault();
        copyDiagram();
      }
    });

    const observer = new MutationObserver(() => {
      updateRenderOutputs();
    });
    if (diagramContainer) {
      observer.observe(diagramContainer, { childList: true, subtree: true });
    }

    updateRenderOutputs();
  </script>
</body>
</html>)HTML";

    static const wchar_t kHtmlPart2[] = LR"HTML()HTML";
    static const wchar_t kHtmlPart3[] = LR"HTML()HTML";
    std::wstring html;
    html.reserve(8509);
    html.append(kHtmlPart1);
    html.append(kHtmlPart2);
    html.append(kHtmlPart3);
    ReplaceAll(html, L"{{BODY}}", body);
    ReplaceAll(html, L"{{FORMAT}}", preferSvg ? L"svg" : L"png");
    return html;
}

static bool BuildHtmlFromMmdcRender(const std::wstring& umlText,
                                    const std::wstring& /*sourcePath*/,
                                    bool preferSvg,
                                    std::wstring& outHtml,
                                    std::wstring* outSvg,
                                    std::vector<unsigned char>* outPng) {
    std::wstring body = L"<pre class='mermaid'>" + EscapeForHtmlText(umlText) + L"</pre>";
    outHtml = BuildWebShellHtml(body, preferSvg);
    if (outSvg) {
        outSvg->clear();
    }
    if (outPng) {
        outPng->clear();
    }
    return true;
}

static std::wstring BuildErrorHtml(const std::wstring& message, bool preferSvg) {
    std::wstring safe = EscapeForHtmlText(message);
    return BuildWebShellHtml(L"<div class='err'>" + safe + L"</div>", preferSvg);
}

#else  // MERMAIDJS_WEB_BUILD

static std::wstring BuildShellHtmlWithBody(const std::wstring& body, bool preferSvg) {
    std::wstring html = LR"HTML(<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>MermaidJs Viewer</title>
  <style>
    :root { color-scheme: light dark; }
    html, body { height: 100%; }
    body { margin: 0; background: canvas; color: CanvasText; font: 13px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; position: relative; }
    #toolbar { position: fixed; top: 8px; left: 8px; display: flex; gap: 6px; z-index: 10; }
    #toolbar button, #toolbar select { padding: 6px 10px; border-radius: 6px; border: 1px solid color-mix(in oklab, Canvas 70%, CanvasText 30%); background: color-mix(in oklab, Canvas 92%, CanvasText 8%); color: inherit; font: inherit; cursor: pointer; }
    #toolbar button:hover, #toolbar select:hover { background: color-mix(in oklab, Canvas 88%, CanvasText 12%); }
    #toolbar button:disabled, #toolbar select:disabled { opacity: 0.6; cursor: not-allowed; }
    #root { padding: 56px 8px 8px 8px; display: grid; place-items: start center; }
    img, svg { max-width: 100%; height: auto; }
    .err { padding: 12px 14px; border-radius: 10px; background: color-mix(in oklab, Canvas 85%, red 15%); }
  </style>
</head>
<body data-format="{{FORMAT}}" data-source-name="{{SOURCE_NAME}}">
  <div id="toolbar">
    <button id="btn-refresh" type="button">Refresh</button>
    <button id="btn-save" type="button">Save as...</button>
    <select id="format-select">
      <option value="svg">SVG</option>
      <option value="png">PNG</option>
    </select>
    <button id="btn-copy" type="button">Copy to clipboard</button>
  </div>
  <div id="root">
    {{BODY}}
  </div>
  <script>
    const hookButton = (btn, messageType) => {
      if (!btn) {
        return;
      }
      const update = () => {
        const connected = !!(window.chrome && window.chrome.webview);
        btn.disabled = !connected;
        if (!connected) {
          btn.title = 'Available inside Total Commander';
          window.setTimeout(update, 1000);
        } else {
          btn.removeAttribute('title');
        }
      };
      update();
      btn.addEventListener('click', () => {
        if (window.chrome && window.chrome.webview) {
          window.chrome.webview.postMessage({ type: messageType });
        }
      });
    };
    hookButton(document.getElementById('btn-refresh'), 'refresh');
    hookButton(document.getElementById('btn-save'), 'saveAs');
    const select = document.getElementById('format-select');
    if (select) {
      const setDisabled = (disabled) => {
        if (disabled) {
          select.setAttribute('disabled', 'disabled');
        } else {
          select.removeAttribute('disabled');
        }
      };
      const update = () => {
        const connected = !!(window.chrome && window.chrome.webview);
        setDisabled(!connected);
        if (!connected) {
          select.title = 'Available inside Total Commander';
          window.setTimeout(update, 1000);
        } else {
          select.removeAttribute('title');
        }
      };
      const initial = document.body?.dataset?.format;
      if (initial) {
        select.value = initial;
      }
      select.addEventListener('change', () => {
        if (document.body && document.body.dataset) {
          document.body.dataset.format = select.value;
        }
        if (typeof updateCopyState === 'function') {
          updateCopyState();
        }
        if (window.chrome && window.chrome.webview) {
          window.chrome.webview.postMessage({ type: 'setFormat', format: select.value });
        }
      });
      update();
    }
    const copyButton = document.getElementById('btn-copy');
    const copyWithWebApi = async () => {
      if (!navigator.clipboard) {
        return false;
      }
      const svg = document.querySelector('svg');
      if (svg) {
        const s = new XMLSerializer().serializeToString(svg);
        await navigator.clipboard.writeText(s);
        return true;
      }
      const img = document.querySelector('img');
      if (img) {
        if (!window.ClipboardItem) {
          return false;
        }
        const c = document.createElement('canvas');
        c.width = img.naturalWidth;
        c.height = img.naturalHeight;
        const g = c.getContext('2d');
        g.drawImage(img, 0, 0);
        const blob = await new Promise(r => c.toBlob(r, 'image/png'));
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
        return true;
      }
      return false;
    };
    const triggerCopy = async () => {
      try {
        if (window.chrome && window.chrome.webview) {
          window.chrome.webview.postMessage({ type: 'copy' });
        } else {
          await copyWithWebApi();
        }
      } catch (e) {}
    };
    let updateCopyState = null;
    if (copyButton) {
      updateCopyState = () => {
        const connected = !!(window.chrome && window.chrome.webview);
        const format = document.body?.dataset?.format || 'svg';
        const clipboardItemAvailable = typeof window.ClipboardItem !== 'undefined';
        const webApiAvailable = !!navigator.clipboard && (format !== 'png' || clipboardItemAvailable);
        if (connected) {
          copyButton.disabled = false;
          copyButton.removeAttribute('title');
        } else if (webApiAvailable) {
          copyButton.disabled = false;
          copyButton.title = 'Host unavailable – using browser clipboard';
          window.setTimeout(updateCopyState, 1000);
        } else {
          copyButton.disabled = true;
          copyButton.title = format === 'png' && !clipboardItemAvailable
            ? 'Clipboard image support is unavailable'
            : 'Clipboard access is unavailable';
          window.setTimeout(updateCopyState, 1000);
        }
      };
      updateCopyState();
      copyButton.addEventListener('click', triggerCopy);
    }
    document.addEventListener('keydown', async ev => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'c') {
        ev.preventDefault();
        await triggerCopy();
      }
    });
  </script>
</body>
</html>)HTML";
    ReplaceAll(html, L"{{BODY}}", body);
    ReplaceAll(html, L"{{FORMAT}}", preferSvg ? L"svg" : L"png");
    return html;
}

static bool BuildHtmlFromMmdcRender(const std::wstring& umlText,
                                    const std::wstring& /*sourcePath*/,
                                    bool preferSvg,
                                    std::wstring& outHtml,
                                    std::wstring* outSvg,
                                    std::vector<unsigned char>* outPng) {
    std::wstring svgOut;
    std::vector<unsigned char> pngOut;
    if (!RunMmdcCli(umlText, preferSvg, svgOut, pngOut)) {
        return false;
    }

    if (preferSvg) {
        outHtml = BuildShellHtmlWithBody(svgOut, true);
    } else {
        const std::string b64 = Base64(pngOut);
        std::wstring body = L"<img alt=\"diagram\" src=\"data:image/png;base64,";
        body += FromUtf8(b64);
        body += L"\"/>";
        outHtml = BuildShellHtmlWithBody(body, false);
    }
    if (outSvg) {
        *outSvg = std::move(svgOut);
    }
    if (outPng) {
        *outPng = std::move(pngOut);
    }
    return true;
}

static std::wstring BuildErrorHtml(const std::wstring& message, bool preferSvg) {
    std::wstring safe = message;
    ReplaceAll(safe, L"<", L"&lt;");
    ReplaceAll(safe, L">", L"&gt;");
    return BuildShellHtmlWithBody(L"<div class='err'>"+safe+L"</div>", preferSvg);
}

#endif  // MERMAIDJS_WEB_BUILD
// ---------------------- WebView host ----------------------
static const wchar_t* kWndClass = L"PumlWebViewHost";

struct Host {
    std::atomic<long> refs{1};
    std::atomic<bool> closing{false};

    std::mutex stateMutex;

    HWND hwnd = nullptr;
    HINSTANCE hInst = nullptr;
    HMODULE   hWvLoader = nullptr;

    ComPtr<ICoreWebView2Environment> env;
    ComPtr<ICoreWebView2Controller>  ctrl;
    ComPtr<ICoreWebView2>            web;
    EventRegistrationToken           navCompletedToken{};
    EventRegistrationToken           webMessageToken{};
    bool                             navCompletedRegistered = false;
    bool                             webMessageRegistered   = false;

    std::wstring initialHtml; // what we will NavigateToString()
    std::wstring sourceFilePath;
    std::wstring lastSvg;
    std::vector<unsigned char> lastPng;
    bool lastPreferSvg = true;
    bool hasRender = false;
};

static void HostNavigateToInitialHtml(Host* host) {
    if (!host || !host->web) return;
    std::wstring html;
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        html = host->initialHtml;
    }
    if (!html.empty()) {
        AppendLog(L"HostNavigateToInitialHtml: navigating with HTML length=" + std::to_wstring(html.size()));
        host->web->NavigateToString(html.c_str());
    }
}

static void HostAddRef(Host* host) {
    if (host) host->refs.fetch_add(1, std::memory_order_relaxed);
}

static void HostRelease(Host* host) {
    if (!host) return;
    if (host->refs.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        delete host;
    }
}

static bool HostRenderAndReload(Host* host,
                                bool preferSvg,
                                const std::wstring& logContext,
                                const std::wstring& failureDialogMessage,
                                bool showDialogOnFailure) {
    if (!host) {
        return false;
    }

    std::wstring sourcePath;
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        sourcePath = host->sourceFilePath;
    }

    if (sourcePath.empty()) {
        AppendLog(logContext + L": no source path recorded");
        {
            std::lock_guard<std::mutex> lock(host->stateMutex);
            host->lastPreferSvg = preferSvg;
        }
        if (showDialogOnFailure && host->hwnd) {
            MessageBoxW(host->hwnd,
                        L"Unable to render because the original file path is unknown.",
                        L"MermaidJs Viewer",
                        MB_OK | MB_ICONERROR);
        }
        return false;
    }

    AppendLog(logContext + L": reloading file " + sourcePath);
    const std::wstring text = ReadFileUtf16OrAnsi(sourcePath.c_str());
    AppendLog(logContext + L": file characters=" + std::to_wstring(text.size()));

    std::wstring html;
    std::wstring svg;
    std::vector<unsigned char> png;
    std::wstring htmlToNavigate;

    if (BuildHtmlFromMmdcRender(text, sourcePath, preferSvg, html, &svg, &png)) {
        AppendLog(logContext + L": render succeeded");
        std::wstring preparedHtml = html;
        ApplySourceNamePlaceholder(preparedHtml, sourcePath);
        {
            std::lock_guard<std::mutex> lock(host->stateMutex);
            host->initialHtml = std::move(preparedHtml);
            host->lastPreferSvg = preferSvg;
#if MERMAIDJS_WEB_BUILD
            host->lastSvg.clear();
            host->lastPng.clear();
            host->hasRender = false;
#else
            host->lastSvg = std::move(svg);
            host->lastPng = std::move(png);
            host->hasRender = true;
#endif
            htmlToNavigate = host->initialHtml;
        }
    } else {
        AppendLog(logContext + L": render failed");
        const std::wstring dialogMessage = failureDialogMessage.empty()
            ? std::wstring(L"Unable to render the diagram. Check the log for details.")
            : failureDialogMessage;
        std::wstring errorHtml = BuildErrorHtml(dialogMessage, preferSvg);
        ApplySourceNamePlaceholder(errorHtml, sourcePath);
        {
            std::lock_guard<std::mutex> lock(host->stateMutex);
            host->initialHtml = std::move(errorHtml);
            host->lastSvg.clear();
            host->lastPng.clear();
            host->lastPreferSvg = preferSvg;
            host->hasRender = false;
            htmlToNavigate = host->initialHtml;
        }
        if (showDialogOnFailure && host->hwnd) {
            MessageBoxW(host->hwnd, dialogMessage.c_str(), L"MermaidJs Viewer", MB_OK | MB_ICONERROR);
        }
    }

    if (host->web && !htmlToNavigate.empty()) {
        host->web->NavigateToString(htmlToNavigate.c_str());
    }

    return true;
}

static void HostHandleSaveAs(Host* host) {
    if (!host) return;

    std::wstring svgCopy;
    std::vector<unsigned char> pngCopy;
    std::wstring sourcePath;
    bool preferSvg = true;
    bool hasRender = false;
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        hasRender = host->hasRender;
        preferSvg = host->lastPreferSvg;
        svgCopy = host->lastSvg;
        pngCopy = host->lastPng;
        sourcePath = host->sourceFilePath;
    }

    if (!hasRender) {
        AppendLog(L"HostHandleSaveAs: no render available");
        MessageBoxW(host->hwnd, L"There is no rendered diagram available to save.", L"MermaidJs Viewer", MB_OK | MB_ICONINFORMATION);
        return;
    }

    const std::wstring defaultExt = preferSvg ? L"svg" : L"png";
    std::wstring suggestedName = L"diagram." + defaultExt;
    if (!sourcePath.empty()) {
        const wchar_t* fileName = PathFindFileNameW(sourcePath.c_str());
        if (fileName && *fileName) {
            suggestedName.assign(fileName);
            size_t dot = suggestedName.find_last_of(L'.');
            if (dot != std::wstring::npos) {
                suggestedName.erase(dot);
            }
            suggestedName += L"." + defaultExt;
        }
    }

    std::wstring fileBuf(MAX_PATH, L'\0');
    lstrcpynW(fileBuf.data(), suggestedName.c_str(), static_cast<int>(fileBuf.size()));

    std::wstring filterSvg = L"Scalable Vector Graphics (*.svg)\0*.svg\0All Files (*.*)\0*.*\0\0";
    std::wstring filterPng = L"Portable Network Graphics (*.png)\0*.png\0All Files (*.*)\0*.*\0\0";

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = host->hwnd;
    ofn.lpstrFile = fileBuf.data();
    ofn.nMaxFile = static_cast<DWORD>(fileBuf.size());
    ofn.lpstrFilter = preferSvg ? filterSvg.c_str() : filterPng.c_str();
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = defaultExt.c_str();
    ofn.lpstrTitle = L"Save MermaidJs Output";

    if (!GetSaveFileNameW(&ofn)) {
        DWORD dlgErr = CommDlgExtendedError();
        if (dlgErr != 0) {
            AppendLog(L"HostHandleSaveAs: GetSaveFileNameW failed (CommDlgExtendedError=" + std::to_wstring(dlgErr) + L")");
            MessageBoxW(host->hwnd, L"Unable to open the save dialog.", L"MermaidJs Viewer", MB_OK | MB_ICONERROR);
        } else {
            AppendLog(L"HostHandleSaveAs: user cancelled save dialog");
        }
        return;
    }

    std::wstring savePath(ofn.lpstrFile);
    bool success = false;
    if (preferSvg) {
        std::string utf8 = ToUtf8(svgCopy);
        if (!svgCopy.empty() && utf8.empty()) {
            AppendLog(L"HostHandleSaveAs: failed to encode SVG as UTF-8");
            success = false;
        } else {
            success = WriteBufferToFile(savePath, utf8.data(), utf8.size());
        }
    } else {
        success = WriteBufferToFile(savePath, pngCopy.data(), pngCopy.size());
    }

    if (!success) {
        MessageBoxW(host->hwnd, L"Failed to save the file.", L"MermaidJs Viewer", MB_OK | MB_ICONERROR);
        return;
    }

    AppendLog(L"HostHandleSaveAs: saved diagram to " + savePath);
}

static void HostHandleRefresh(Host* host) {
    if (!host) return;

    bool preferSvg = true;
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        preferSvg = host->lastPreferSvg;
    }

    HostRenderAndReload(host,
                        preferSvg,
                        L"HostHandleRefresh",
                        L"Unable to refresh the diagram. Check the log for details.",
                        true);
}

static void HostHandleFormatChange(Host* host, bool preferSvg) {
    if (!host) return;

#if MERMAIDJS_WEB_BUILD
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        host->lastPreferSvg = preferSvg;
    }
    AppendLog(L"HostHandleFormatChange: updated preferred format to " + std::wstring(preferSvg ? L"SVG" : L"PNG"));
#else
    const std::wstring formatLabel = preferSvg ? L"svg" : L"png";
    const std::wstring logContext = std::wstring(L"HostHandleFormatChange(") + formatLabel + L")";
    const std::wstring errorMessage = preferSvg
        ? std::wstring(L"Unable to render the diagram as SVG. Check the log for details.")
        : std::wstring(L"Unable to render the diagram as PNG. Check the log for details.");

    HostRenderAndReload(host,
                        preferSvg,
                        logContext,
                        errorMessage,
                        true);
#endif
}

static void HostHandleRenderUpdate(Host* host,
                                   const std::wstring& format,
                                   const std::wstring& svgBase64,
                                   const std::wstring& pngBase64) {
#if !MERMAIDJS_WEB_BUILD
    (void)host;
    (void)format;
    (void)svgBase64;
    (void)pngBase64;
#else
    if (!host) {
        return;
    }

    const std::wstring loweredFormat = ToLowerTrim(format);
    const bool preferSvg = loweredFormat.empty() ? true : (loweredFormat != L"png");

    std::vector<unsigned char> svgBytes = Base64Decode(svgBase64);
    std::wstring svgText;
    if (!svgBytes.empty()) {
        std::string utf8(svgBytes.begin(), svgBytes.end());
        svgText = FromUtf8(utf8);
    }
    std::vector<unsigned char> pngBytes = Base64Decode(pngBase64);

    const size_t svgByteCount = svgBytes.size();
    const size_t pngByteCount = pngBytes.size();

    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        host->lastSvg = std::move(svgText);
        host->lastPng = std::move(pngBytes);
        host->lastPreferSvg = preferSvg;
        host->hasRender = preferSvg ? !host->lastSvg.empty() : !host->lastPng.empty();
    }

    std::wstringstream log;
    log << L"HostHandleRenderUpdate: received render payload (svgBytes="
        << static_cast<unsigned long long>(svgByteCount)
        << L", pngBytes=" << static_cast<unsigned long long>(pngByteCount)
        << L", preferSvg=" << (preferSvg ? L"true" : L"false") << L")";
    AppendLog(log.str());
#endif
}

static void HostHandleCopy(Host* host) {
    if (!host) {
        return;
    }

    std::wstring svgCopy;
    std::vector<unsigned char> pngCopy;
    bool preferSvg = true;
    bool hasRender = false;
    {
        std::lock_guard<std::mutex> lock(host->stateMutex);
        hasRender = host->hasRender;
        preferSvg = host->lastPreferSvg;
        svgCopy = host->lastSvg;
        pngCopy = host->lastPng;
    }

    if (!hasRender) {
        AppendLog(L"HostHandleCopy: no render available");
        MessageBoxW(host->hwnd,
                    L"There is no rendered diagram available to copy.",
                    L"MermaidJs Viewer",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (!OpenClipboard(host->hwnd)) {
        AppendLog(L"HostHandleCopy: OpenClipboard failed with error " + std::to_wstring(GetLastError()));
        MessageBoxW(host->hwnd,
                    L"Unable to access the clipboard.",
                    L"MermaidJs Viewer",
                    MB_OK | MB_ICONERROR);
        return;
    }

    bool emptied = EmptyClipboard() != FALSE;
    if (!emptied) {
        AppendLog(L"HostHandleCopy: EmptyClipboard failed with error " + std::to_wstring(GetLastError()));
        CloseClipboard();
        MessageBoxW(host->hwnd,
                    L"Unable to clear the clipboard.",
                    L"MermaidJs Viewer",
                    MB_OK | MB_ICONERROR);
        return;
    }

    bool success = false;

    if (preferSvg) {
        if (!svgCopy.empty()) {
            success = ClipboardSetUnicodeText(svgCopy);
            if (!success) {
                AppendLog(L"HostHandleCopy: failed to place SVG text on the clipboard");
            }
        } else {
            AppendLog(L"HostHandleCopy: SVG buffer is empty");
        }
    } else {
        if (!pngCopy.empty()) {
            std::vector<unsigned char> dib;
            bool dibOk = false;
            if (CreateDibFromPng(pngCopy, dib)) {
                dibOk = ClipboardSetBinaryData(CF_DIB, dib.data(), dib.size());
                if (!dibOk) {
                    AppendLog(L"HostHandleCopy: failed to place CF_DIB bitmap on the clipboard");
                }
            } else {
                AppendLog(L"HostHandleCopy: failed to convert PNG to DIB");
            }
            UINT pngFormat = RegisterClipboardFormatW(L"PNG");
            bool pngOk = false;
            if (pngFormat != 0) {
                pngOk = ClipboardSetBinaryData(pngFormat, pngCopy.data(), pngCopy.size());
                if (!pngOk) {
                    AppendLog(L"HostHandleCopy: failed to place PNG data on the clipboard");
                }
            } else {
                AppendLog(L"HostHandleCopy: RegisterClipboardFormatW(PNG) failed");
            }
            success = dibOk || pngOk;
        } else {
            AppendLog(L"HostHandleCopy: PNG buffer is empty");
        }
    }

    CloseClipboard();

    if (!success) {
        MessageBoxW(host->hwnd,
                    L"Failed to copy the diagram to the clipboard.",
                    L"MermaidJs Viewer",
                    MB_OK | MB_ICONERROR);
    } else {
        AppendLog(L"HostHandleCopy: copied diagram as " + std::wstring(preferSvg ? L"SVG" : L"PNG"));
    }
}

typedef HRESULT (STDAPICALLTYPE *PFN_CreateCoreWebView2EnvironmentWithOptions)(
    PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);

static LRESULT CALLBACK HostWndProc(HWND h, UINT m, WPARAM w, LPARAM l){
    if(m==WM_SIZE){
        auto* host = reinterpret_cast<Host*>(GetWindowLongPtrW(h, GWLP_USERDATA));
        if(host && host->ctrl){
            RECT rc; GetClientRect(h, &rc);
            host->ctrl->put_Bounds(rc);
        }
    }
    if(m==WM_NCDESTROY){
        auto* host = reinterpret_cast<Host*>(GetWindowLongPtrW(h, GWLP_USERDATA));
        if(host){
            host->closing.store(true, std::memory_order_release);
            host->hwnd = nullptr;
            if (host->web && host->navCompletedRegistered) {
                host->web->remove_NavigationCompleted(host->navCompletedToken);
                host->navCompletedRegistered = false;
                HostRelease(host);
            }
            if (host->web && host->webMessageRegistered) {
                host->web->remove_WebMessageReceived(host->webMessageToken);
                host->webMessageRegistered = false;
                HostRelease(host);
            }
            if(host->ctrl) host->ctrl->Close();
            if(host->hWvLoader) FreeLibrary(host->hWvLoader);
            host->ctrl.Reset();
            host->web.Reset();
            host->env.Reset();
            HostRelease(host);
        }
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
    }
    return DefWindowProcW(h, m, w, l);
}

static void EnsureWndClass(){
    static bool inited = false;
    if(inited) return;
    WNDCLASSW wc{}; wc.lpfnWndProc = HostWndProc;
    wc.hInstance   = GetModuleHandleW(nullptr);
    wc.hCursor     = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = kWndClass;
    RegisterClassW(&wc);
    inited = true;
}

static void InitWebView(struct Host* host){
    AppendLog(L"InitWebView: loading WebView2Loader.dll");
    std::wstring loaderPath = GetModuleDir() + L"\\WebView2Loader.dll";
    host->hWvLoader = LoadLibraryW(loaderPath.c_str());
    if(!host->hWvLoader){
        AppendLog(L"InitWebView: WebView2Loader.dll not found at " + loaderPath +
                  L" (error=" + std::to_wstring(GetLastError()) + L")");
        host->hWvLoader = LoadLibraryW(L"WebView2Loader.dll");
    }
    if(!host->hWvLoader){
        AppendLog(L"InitWebView: WebView2Loader.dll load failed");
        CreateWindowW(L"STATIC", L"WebView2 Runtime not found. Install Edge WebView2 Runtime.", WS_CHILD|WS_VISIBLE|SS_CENTER,
                      0,0,0,0, host->hwnd, nullptr, host->hInst, nullptr);
        return;
    }
    auto fn = reinterpret_cast<PFN_CreateCoreWebView2EnvironmentWithOptions>(
        GetProcAddress(host->hWvLoader, "CreateCoreWebView2EnvironmentWithOptions"));
    if(!fn){
        AppendLog(L"InitWebView: CreateCoreWebView2EnvironmentWithOptions entry not found");
        CreateWindowW(L"STATIC", L"WebView2 loader entry not found.", WS_CHILD|WS_VISIBLE|SS_CENTER,
                      0,0,0,0, host->hwnd, nullptr, host->hInst, nullptr);
        return;
    }

    AppendLog(L"InitWebView: creating environment");
    HostAddRef(host);
    auto envCompleted = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [host](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            std::unique_ptr<Host, decltype(&HostRelease)> guard(host, &HostRelease);
            if(!host || host->closing.load(std::memory_order_acquire)){
                AppendLog(L"InitWebView: host closing before environment callback");
                return S_OK;
            }
            if(FAILED(hr) || !env){
                AppendLog(L"InitWebView: environment creation failed with HRESULT=" + std::to_wstring(hr));
                return S_OK;
            }
            AppendLog(L"InitWebView: environment ready");
            host->env = env;

            HostAddRef(host);
            auto controllerCompleted = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                [host](HRESULT hrCtrl, ICoreWebView2Controller* ctrl) -> HRESULT {
                    std::unique_ptr<Host, decltype(&HostRelease)> guard(host, &HostRelease);
                    if(!host || host->closing.load(std::memory_order_acquire)){
                        AppendLog(L"InitWebView: host closing before controller callback");
                        return S_OK;
                    }
                    if(FAILED(hrCtrl) || !ctrl){
                        AppendLog(L"InitWebView: controller creation failed with HRESULT=" + std::to_wstring(hrCtrl));
                        return S_OK;
                    }
                    AppendLog(L"InitWebView: controller ready");
                    host->ctrl = ctrl;
                    host->ctrl->get_CoreWebView2(&host->web);
                    if (!host->web) {
                        AppendLog(L"InitWebView: failed to get CoreWebView2 interface");
                        return S_OK;
                    }
                    AppendLog(L"InitWebView: CoreWebView2 obtained");
                    if(!host->hwnd){
                        AppendLog(L"InitWebView: window destroyed before bounds update");
                        return S_OK;
                    }
                    RECT rc; GetClientRect(host->hwnd, &rc);
                    host->ctrl->put_Bounds(rc);

                    HostAddRef(host);
                    auto webMessageHandler = Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                        [host](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                            HostAddRef(host);
                            std::unique_ptr<Host, decltype(&HostRelease)> guard(host, &HostRelease);
                            if (!host || host->closing.load(std::memory_order_acquire)) {
                                return S_OK;
                            }
                            if (!args) {
                                return S_OK;
                            }

                            LPWSTR rawJson = nullptr;
                            HRESULT hrJson = args->get_WebMessageAsJson(&rawJson);
                            if (SUCCEEDED(hrJson) && rawJson) {
                                std::wstring json(rawJson);
                                CoTaskMemFree(rawJson);

                                const std::wstring type = ToLowerTrim(ExtractJsonStringField(json, L"type"));
                                if (type == L"saveas") {
                                    HostHandleSaveAs(host);
                                } else if (type == L"refresh") {
                                    HostHandleRefresh(host);
                                } else if (type == L"setformat") {
                                    std::wstring format = ToLowerTrim(ExtractJsonStringField(json, L"format"));
                                    const bool preferSvg = format != L"png";
                                    HostHandleFormatChange(host, preferSvg);
                                } else if (type == L"copy") {
                                    HostHandleCopy(host);
                                } else if (type == L"rendered") {
#if MERMAIDJS_WEB_BUILD
                                    std::wstring format = ExtractJsonStringField(json, L"format");
                                    std::wstring svgB64 = ExtractJsonStringField(json, L"svgBase64");
                                    std::wstring pngB64 = ExtractJsonStringField(json, L"pngBase64");
                                    HostHandleRenderUpdate(host, format, svgB64, pngB64);
#endif
                                }
                            } else if (rawJson) {
                                CoTaskMemFree(rawJson);
                            }
                            return S_OK;
                        });
                    EventRegistrationToken msgToken{};
                    HRESULT hrMsg = host->web->add_WebMessageReceived(webMessageHandler.Get(), &msgToken);
                    if (SUCCEEDED(hrMsg)) {
                        host->webMessageToken = msgToken;
                        host->webMessageRegistered = true;
                    } else {
                        AppendLog(L"InitWebView: add_WebMessageReceived failed with HRESULT=" + std::to_wstring(hrMsg));
                        HostRelease(host);
                    }

                    HostAddRef(host);
                    auto navCompletedHandler = Callback<ICoreWebView2NavigationCompletedEventHandler>(
                        [host](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs* args) -> HRESULT {
                            HostAddRef(host);
                            std::unique_ptr<Host, decltype(&HostRelease)> guard(host, &HostRelease);
                            if(!host || host->closing.load(std::memory_order_acquire)){
                                return S_OK;
                            }
                            UINT64 navId = 0;
                            if (args) args->get_NavigationId(&navId);
                            BOOL isSuccess = FALSE;
                            if (args) args->get_IsSuccess(&isSuccess);
                            COREWEBVIEW2_WEB_ERROR_STATUS status = COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN;
                            if (args) args->get_WebErrorStatus(&status);
                            std::wstringstream os;
                            os << L"InitWebView: NavigationCompleted id=" << navId
                               << L", success=" << (isSuccess ? L"true" : L"false")
                               << L", webErrorStatus=" << static_cast<int>(status);
                            AppendLog(os.str());
                            return S_OK;
                        });
                    EventRegistrationToken navToken{};
                    HRESULT hrNav = host->web->add_NavigationCompleted(navCompletedHandler.Get(), &navToken);
                    if (SUCCEEDED(hrNav)) {
                        host->navCompletedToken = navToken;
                        host->navCompletedRegistered = true;
                    } else {
                        AppendLog(L"InitWebView: add_NavigationCompleted failed with HRESULT=" + std::to_wstring(hrNav));
                        HostRelease(host);
                    }

                    {
                        std::lock_guard<std::mutex> lock(host->stateMutex);
                        if (!host->initialHtml.empty()){
                            AppendLog(L"InitWebView: navigating to initial HTML (" + std::to_wstring(host->initialHtml.size()) + L" chars)");
                        }
                    }
                    HostNavigateToInitialHtml(host);
                    return S_OK;
                });

            HRESULT hrCtrl = env->CreateCoreWebView2Controller(host->hwnd, controllerCompleted.Get());
            if(FAILED(hrCtrl)){
                AppendLog(L"InitWebView: CreateCoreWebView2Controller call failed with HRESULT=" + std::to_wstring(hrCtrl));
                HostRelease(host);
            }
            return S_OK;
        });

    HRESULT hrEnv = fn(nullptr, nullptr, nullptr, envCompleted.Get());
    if(FAILED(hrEnv)){
        AppendLog(L"InitWebView: CreateCoreWebView2EnvironmentWithOptions call failed with HRESULT=" + std::to_wstring(hrEnv));
        HostRelease(host);
    }
}


// ---------------------- WLX exports ----------------------
extern "C" {

__declspec(dllexport) int __stdcall ListGetDetectString(char* DetectString, int maxlen) {
    LoadConfigIfNeeded();
    lstrcpynA(DetectString, g_detectA.c_str(), maxlen);
    return 0;
}

__declspec(dllexport) HWND __stdcall ListLoadW(HWND ParentWin, wchar_t* FileToLoad, int /*ShowFlags*/) {
    LoadConfigIfNeeded();
    AppendLog(L"ListLoadW: start for file " + std::wstring(FileToLoad ? FileToLoad : L"<null>"));
    EnsureWndClass();

    auto* host = new Host();
    host->hInst = GetModuleHandleW(nullptr);
    host->hwnd  = CreateWindowExW(0, kWndClass, L"",
                                  WS_CHILD|WS_VISIBLE, 0,0,0,0,
                                  ParentWin, nullptr, host->hInst, nullptr);
    if(!host->hwnd){
        AppendLog(L"ListLoadW: CreateWindowExW failed with error " + std::to_wstring(GetLastError()));
        HostRelease(host);
        return nullptr;
    }
    SetWindowLongPtrW(host->hwnd, GWLP_USERDATA, (LONG_PTR)host);

    const std::wstring text = ReadFileUtf16OrAnsi(FileToLoad);
    AppendLog(L"ListLoadW: loaded file characters=" + std::to_wstring(text.size()));
    const bool preferSvg = (ToLowerTrim(g_prefer) == L"svg");
    AppendLog(L"ListLoadW: preferSvg=" + std::wstring(preferSvg ? L"true" : L"false"));

    std::wstring sourcePath = FileToLoad ? std::wstring(FileToLoad) : std::wstring();
#if MERMAIDJS_WEB_BUILD
    AppendLog(L"ListLoadW: preparing web-based rendering");
#else
    AppendLog(L"ListLoadW: attempting Mermaid CLI render with cli=" + (g_mmdcPath.empty() ? std::wstring(L"<auto>") : g_mmdcPath));
#endif
    std::wstring html;
    std::wstring svg;
    std::vector<unsigned char> png;
    if (BuildHtmlFromMmdcRender(text, sourcePath, preferSvg, html, &svg, &png)) {
        std::wstring preparedHtml = html;
        ApplySourceNamePlaceholder(preparedHtml, sourcePath);
        {
            std::lock_guard<std::mutex> lock(host->stateMutex);
            host->initialHtml = std::move(preparedHtml);
            host->sourceFilePath = std::move(sourcePath);
            host->lastPreferSvg = preferSvg;
            host->hasRender = false;
#if MERMAIDJS_WEB_BUILD
            host->lastSvg.clear();
            host->lastPng.clear();
#else
            host->lastSvg = std::move(svg);
            host->lastPng = std::move(png);
            host->hasRender = true;
#endif
        }
#if MERMAIDJS_WEB_BUILD
        AppendLog(L"ListLoadW: web render prepared");
#else
        AppendLog(L"ListLoadW: local render succeeded" + std::wstring(preferSvg ? L" (SVG)" : L" (PNG)"));
#endif
    } else {
#if MERMAIDJS_WEB_BUILD
        const std::wstring lastErr = L"Unable to prepare the diagram for web rendering.";
#else
        const std::wstring lastErr = L"Local Mermaid CLI rendering failed. Check mmdc.bat path in the INI file.";
#endif
        {
            std::lock_guard<std::mutex> lock(host->stateMutex);
            host->initialHtml = BuildErrorHtml(lastErr, preferSvg);
            ApplySourceNamePlaceholder(host->initialHtml, sourcePath);
            host->sourceFilePath = std::move(sourcePath);
            host->lastPreferSvg = preferSvg;
            host->lastSvg.clear();
            host->lastPng.clear();
            host->hasRender = false;
        }
#if MERMAIDJS_WEB_BUILD
        AppendLog(L"ListLoadW: web render failed -> " + lastErr);
#else
        AppendLog(L"ListLoadW: Mermaid CLI error message -> " + lastErr);
        AppendLog(L"ListLoadW: local render failed");
#endif
        AppendLog(L"ListLoadW: showing error HTML");
    }

    InitWebView(host);
    AppendLog(L"ListLoadW: InitWebView invoked");
    return host->hwnd;
}

__declspec(dllexport) int __stdcall ListSendCommand(HWND /*ListWin*/, int /*Command*/, int /*Parameter*/) {
    // Ctrl+C is handled by the web page JS.
    return 0;
}

__declspec(dllexport) void __stdcall ListCloseWindow(HWND ListWin) {
    AppendLog(L"ListCloseWindow: destroying window");
    DestroyWindow(ListWin);
}

} // extern "C"
