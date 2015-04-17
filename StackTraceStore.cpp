#include <Windows.h>
#include <map>
#include <vector>
#include "StackTraceStore.h"


using namespace std;

#define STACK_DEPTH 32
#define STACK_COUNT 1024
#define TIMESTAMP_COUNT 14

#pragma pack(push,1)
class DynamicCallThunk
{
	struct CallThunk
	{
//		BYTE   push;          // push new-proc
		DWORD enterpush;
		DWORD  proc;      // so a subsequent ret instruction takes the newproc and return
		BYTE    jmp;          // jmp loggingproc
		DWORD  relloggingproc;         // relative call
		bool Init(DWORD_PTR loggingproc, DWORD_PTR newproc)
		{
//			push = 0x68;
			enterpush = 0x68ec8b55;	// push ebp, mov ebp,esp, push new-proc
			proc = newproc;
			jmp = 0xe9;
			relloggingproc = DWORD((INT_PTR)loggingproc - ((INT_PTR)this + sizeof(CallThunk)));

			FlushInstructionCache(GetCurrentProcess(), this, sizeof(CallThunk));
			return TRUE;
		}
		void* GetCodeAddress(){return this;}
		void* operator new(size_t){return VirtualAlloc(0, sizeof(CallThunk), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);}
		void operator delete(void* pThunk){VirtualFree(pThunk, 0, MEM_RELEASE);}
	}* thunk_;
public:
	DynamicCallThunk() : thunk_(0){}
	~DynamicCallThunk() {delete thunk_;}

	bool Init(DWORD_PTR loggingproc, DWORD_PTR newproc)
	{
		if (! thunk_) thunk_ = new CallThunk;
		if (! thunk_) return false;
		return thunk_->Init(loggingproc, newproc);
	}

	void* GetCodeAddress(){return thunk_->GetCodeAddress();}
};
#pragma pack(pop)

class StackTraceStore
{
#define JUMP_BACK 0xF9EB
#define MOV_EDI_EDI 0xFF8B
	bool HotPatch(void *original, void *customized)
	{
		bool ret = false;
		DWORD	protect = NULL;

		WORD& JumpBack = *(WORD*)original;
		BYTE& LongJump = *((BYTE*)original - 5);
		DWORD& LongJumpAddr = *((DWORD*)original - 1);

		if(! VirtualProtect(&LongJump, 20, PAGE_EXECUTE_WRITECOPY, &protect))
			return false;

		if (MOV_EDI_EDI == JumpBack)
		{
			LongJump = 0xE9;
			LongJumpAddr = ((DWORD)customized) - ((DWORD)original);
			JumpBack = JUMP_BACK;
			ret = true;
		}
		VirtualProtect(&LongJump, 20, protect, &protect);
		return ret;
	}

	bool HotUnpatch(void*original)
	{
		bool bRet = false;
		DWORD	protect = NULL;

		WORD& JumpBack = *(WORD*)original;

		if (! VirtualProtect(&JumpBack, 2, PAGE_EXECUTE_WRITECOPY, &protect))
			return false;

		if (JUMP_BACK == JumpBack)
		{
			JumpBack = MOV_EDI_EDI;
			bRet = true;
		}

		VirtualProtect(&JumpBack, 2, protect, &protect);
		return bRet;
	}
public:
	struct StackTraceEntry
	{
		StackTraceEntry(){ZeroMemory(this, sizeof(StackTraceEntry));}
		DWORD hash;
		DWORD frames[STACK_DEPTH];
		DWORD timestamps[TIMESTAMP_COUNT];
		DWORD hit;
	};

	StackTraceStore()
	{
		InitializeCriticalSection(&lock_);
		store_.reserve(STACK_COUNT);
	}

	~StackTraceStore()
	{
		DeleteCriticalSection(&lock_);
	}

	bool StoreStackBackTrace()
	{
		StackTraceEntry e;
		WORD depth = RtlCaptureStackBackTrace(1, STACK_DEPTH, (PVOID*)e.frames, &e.hash);
		if (depth)
		{
			EnterCriticalSection(&lock_);
			for (unsigned int i = 0; i < store_.size(); i ++)
			{
				StackTraceEntry& item = store_[i];
				if (item.hash == e.hash)
				{
					item.timestamps[item.hit % TIMESTAMP_COUNT] = GetTickCount();
					item.hit ++;
					LeaveCriticalSection(&lock_);
					return true;
				}
			}

			e.timestamps[0] = GetTickCount();
			e.hit ++;
			store_.push_back(e);
			LeaveCriticalSection(&lock_);
			return true;
		}

		return false;
	}

	static void SafeInvoker()
	{
		__asm {
			push ebp;
			mov ebp, esp
			push eax;
			push ecx;
			push edx;
		}
		_stackTraceStore.StoreStackBackTrace();
		__asm {
			pop edx;
			pop ecx;
			pop eax;
			mov esp, ebp;
			pop ebp;
		}
	}

	// not thread-safe. start monitoring on initialization
	bool StartMonitoring(void* func)
	{
		static unsigned char prolog[5] = {0x8b, 0xff, 0x55, 0x8b, 0xec};
		// at present we only hook API with the prolog of "mov edi, edi; push ebp; mov ebp, esp"
		if (0 != memcmp((void*)prolog, func, 5))
			return false;

		if (thunks_.find(func) != thunks_.end())
			return false;

		thunks_[func].Init((DWORD_PTR)SafeInvoker, int(func) + 5);
		if (! HotPatch(func, thunks_[func].GetCodeAddress()))
		{
			thunks_.erase(func);
			return false;
		}
		return true;
	}

	// suggest not to stop monitoring as it's not really safe to do so.
	bool StopMonitoring(void* func)
	{
		if (thunks_.find(func) == thunks_.end())
			return false;

		if (HotUnpatch(func))
		{
			thunks_.erase(func);	// other threads may be running thunk code, so this isn't safe
			return true;
		}
		return false;
	}

	std::map<void*, DynamicCallThunk> thunks_;
	std::vector<StackTraceEntry> store_;
	CRITICAL_SECTION lock_;
} _stackTraceStore;

bool StoreStackBackTrace()
{
	return _stackTraceStore.StoreStackBackTrace();
}

bool MonitorAPI(void* api)
{
	return _stackTraceStore.StartMonitoring(api);
}

int main(int argc, char* argv[])
{
	MonitorAPI(MessageBox);
	MessageBox(0, 0, 0, 0);
	MessageBox(0, 0, 0, 0);
	return 0;
}

