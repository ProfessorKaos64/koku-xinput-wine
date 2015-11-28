#include "xinput.h"
#include <string>
#include "main.h"
#include "device.h"
#include <iostream>
using namespace std;

#ifdef __LP64__
#warning "Add 64bit support !"
#endif

bool debug = false;

typedef void* WINAPI (*loadlibrary_func_type)(const char* lpFileName);
typedef void* WINAPI (*getprocaddress_func_type)(void* hModule, const char* lpProcName);

static int depth = 0;
std::string depthSpace() {
    return std::string(depth, ' ');
}

extern "C" void *wine_dll_load( const char *filename, char *error, int errorsize, int *file_exists )
{
	debug = (getenv("KOKU_XINPUT_DEBUG") != 0);

	/*
	 This is a wine intern function,
	 we get control of this function via LD_PRELOAD.

	 We check the filenames and hook some functions ;)
	*/

	if (debug)
	{
		clog << depthSpace() << "koku-xinput-wine: ["<< filename <<"] wine_dll_load(\"" << filename << "\", ...);" << endl;
	}

	//call original function:
	depth += 1; 
	void* result = ((decltype(&wine_dll_load))dlsym(RTLD_NEXT, "wine_dll_load"))(filename, error, errorsize, file_exists);
    
	//check for dlls
	if (string("xinput1_3.dll") == filename ||
	    string("xinput1_4.dll") == filename ||
	    string("xinput9_1_0.dll") == filename)
	{
        // try to find Kernel32.dll
        int dummy;
        static void* Kernel32 = ((decltype(&wine_dll_load))dlsym(RTLD_NEXT, "wine_dll_load"))("kernel32.dll", nullptr, 0, &dummy);
        static loadlibrary_func_type LoadLibrary = (loadlibrary_func_type)dlsym(Kernel32, "LoadLibraryA");
        static getprocaddress_func_type GetProcAddress = (getprocaddress_func_type)dlsym(Kernel32, "GetProcAddress");
        static bool tryKernel32Route = Kernel32 && LoadLibrary && GetProcAddress;
        static bool printedOnce = false;
        if (debug && !printedOnce) {
            printedOnce = true;
            if (Kernel32) {
                clog << depthSpace() <<  "koku-xinput-wine: found `kernel32.dll`" << endl;
                if (LoadLibrary) {
                    clog << depthSpace() <<  "koku-xinput-wine: found `LoadLibrary` in `kernel32.dll`" << endl;
                } else {
                    clog << depthSpace() << "koku-xinput-wine: couldn't find `LoadLibrary` in `kernel32.dll`" << endl;
                }
                if (GetProcAddress) {
                    clog << depthSpace() << "koku-xinput-wine: found `GetProcAddress` in `kernel32.dll`" << endl;
                } else {
                    clog << depthSpace() << "koku-xinput-wine: couldn't find `GetProcAddress` in `kernel32.dll`" << endl;
                }
            } else {
                clog << depthSpace() << "koku-xinput-wine: couldn't find `kernel32.dll`" << endl;
            }
        }
		        
		long addr = 0;
		pair<string, void*> list[] =
		{
			{"XInputEnable"                    , (void*)&XInputEnable},
			{"XInputGetAudioDeviceIds"         , (void*)&XInputGetAudioDeviceIds},
			{"XInputGetBatteryInformation"     , (void*)&XInputGetBatteryInformation},
			{"XInputGetCapabilities"           , (void*)&XInputGetCapabilities},
			{"XInputGetDSoundAudioDeviceGuids" , (void*)&XInputGetDSoundAudioDeviceGuids},
			{"XInputGetKeystroke"              , (void*)&XInputGetKeystroke},
			{"XInputGetState"                  , (void*)&XInputGetState},
			{"XInputSetState"                  , (void*)&XInputSetState}
		};
		//hook functions
		for(int i = 0; i < 8; ++i)
		{	    
			addr = long(dlsym(result, list[i].first.c_str()));
			if (debug)
			{
				clog << depthSpace() << "koku-xinput-wine: ["<< filename <<"] search for `" << list[i].first << "`" << endl;
			}
			if (addr != 0)
			{
				if (debug)
				{
					clog << depthSpace() << "koku-xinput-wine: ["<< filename <<"] found `" << list[i].first << "`, redirect it" << endl;
				}
				long addr_start = (addr - PAGESIZE-1) & ~(PAGESIZE-1);
				long addr_end   = (addr + PAGESIZE-1) & ~(PAGESIZE-1);
				mprotect((void*)addr_start, addr_end-addr_start, PROT_READ|PROT_WRITE|PROT_EXEC);
				new ((void*)addr) Sjmp(list[i].second);
			}
			if (addr == 0 && tryKernel32Route) {
			    if (debug) {
			        clog << depthSpace() << "koku-xinput-wine: ["<< filename <<"] search for `" << list[i].first << "` with `kernel32.dll`" << endl;
			    }
			    depth += 1;
		        void* handle = LoadLibrary(filename);
		        depth -= 1;
		        if (handle) {
		            addr = long(GetProcAddress(handle, list[i].first.c_str()));
		            if (addr != 0) {
			            if (debug) {
			                clog << depthSpace() << "koku-xinput-wine: ["<< filename <<"] found `" << list[i].first << "`, redirect it with `kernel32.dll`" << endl;
			            }
			            long addr_start = (addr - PAGESIZE-1) & ~(PAGESIZE-1);
			            long addr_end   = (addr + PAGESIZE-1) & ~(PAGESIZE-1);
			            mprotect((void*)addr_start, addr_end-addr_start, PROT_READ|PROT_WRITE|PROT_EXEC);
			            new ((void*)addr) Sjmp(list[i].second);
		            }
		        }
			}
			
		}
	}
	if (string("ole32.dll") ==  filename)
	{
		DeviceInit(result);
	}
	depth -= 1; 

	return result;
}
