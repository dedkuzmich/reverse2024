#include <windows.h>
#include <iostream>

using namespace std;

typedef HRESULT(WINAPI* URLDownloadToFileA_t)(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);

int main() 
{
    HMODULE hKernel32 = LoadLibraryA("urlmon.dll");
    if (hKernel32 == NULL)
    {
        cerr << "Failed to load urlmon.dll" << endl;
        return 1;
    }

    URLDownloadToFileA_t pURLDownloadToFileA = (URLDownloadToFileA_t)GetProcAddress(hKernel32, "URLDownloadToFileA");
    if (pURLDownloadToFileA == NULL) 
    {
        cerr << "Failed to get URLDownloadToFileA function address" << endl;
        FreeLibrary(hKernel32);
        return 1;
    }

    LPCSTR url = "https://raw.githubusercontent.com/dedkuzmich/png2txt/main/LICENSE";
    LPCSTR filename = "license.txt";

    HRESULT hr = pURLDownloadToFileA(NULL, url, filename, 0, NULL);
    if (hr == S_OK) 
    {
        cout << "File downloaded successfully" << endl;
    }
    else 
    {
        cout << "Failed to download file. HRESULT: " << hr << endl;
    }

    FreeLibrary(hKernel32);
    return 0;
}
